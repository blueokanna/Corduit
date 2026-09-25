pub mod validator;

use nextjson::{NsonDeserialize, NsonSerialize};
use std::collections::HashMap;

/// Main configuration structure
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize, Default)]
pub struct Config {
    /// General settings
    #[serde(default)]
    pub general: GeneralConfig,

    /// DNS configuration
    #[serde(default)]
    pub dns: DnsConfig,

    /// Inbound configurations
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,

    /// Outbound configurations
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,

    /// Routing rules
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

impl Config {
    /// Validate the configuration
    pub fn validate(&self) -> crate::engine::error::Result<()> {
        crate::engine::config::validator::ConfigValidator::validate(self)
    }

    /// Create a new config with validation
    pub fn new_validated(
        general: GeneralConfig,
        dns: DnsConfig,
        inbounds: Vec<InboundConfig>,
        outbounds: Vec<OutboundConfig>,
        rules: Vec<RuleConfig>,
    ) -> crate::engine::error::Result<Self> {
        let config = Self {
            general,
            dns,
            inbounds,
            outbounds,
            rules,
        };
        config.validate()?;
        Ok(config)
    }
}

/// General configuration
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct GeneralConfig {
    /// Listening port for SOCKS5 proxy.
    ///
    /// Read by the TUN startup path to decide which local inbound captured
    /// traffic is handed to.
    pub socks_port: Option<u16>,

    /// Listening port for mixed proxy.
    pub mixed_port: Option<u16>,

    /// Authentication settings
    pub authentication: Option<Vec<AuthenticationConfig>>,

    /// Allow LAN access
    #[serde(default)]
    pub allow_lan: bool,

    /// Address an inbound falls back to when no inbound declares its own listen
    /// address.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Mode: Rule, Global, Direct
    #[serde(default)]
    pub mode: Mode,

    /// Log level
    #[serde(default)]
    pub log_level: LogLevel,

    /// IPv6 support
    #[serde(default)]
    pub ipv6: bool,

    /// Try a name's addresses concurrently instead of one after another.
    ///
    /// A name often has several addresses and only some of them work; dialling
    /// them in order makes the client wait out every dead one. Racing them costs
    /// extra sockets and succeeds as soon as *any* address answers.
    #[serde(default)]
    pub tcp_concurrent: bool,

    /// External controller settings
    pub external_controller: Option<String>,

    /// External UI
    pub external_ui: Option<String>,

    /// Secret for external controller
    pub secret: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            socks_port: None,
            mixed_port: None,
            authentication: None,
            allow_lan: false,
            bind_address: default_bind_address(),
            mode: Mode::default(),
            log_level: LogLevel::default(),
            ipv6: false,
            tcp_concurrent: false,
            external_controller: None,
            external_ui: None,
            secret: None,
        }
    }
}

/// When an answer is suspect enough to re-resolve through the fallback set.
///
/// The reason a fallback set exists at all is poisoning: a tampered answer
/// usually shows up either as an address that has no business being handed out
/// (a private or reserved one), or as a domain the operator already knows is a
/// target. These are the three ways to say "do not trust this answer".
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FallbackFilterConfig {
    /// Treat an answer that resolves into the domestic country as suspect.
    #[serde(default = "default_enabled_true")]
    pub geoip: bool,

    /// Which country the primary resolvers are assumed to sit inside.
    #[serde(default = "default_geoip_code", alias = "geoip_code")]
    pub geoip_code: String,

    /// Networks that make an answer suspect, e.g. `127.0.0.0/8`.
    #[serde(default)]
    pub ipcidr: Vec<String>,

    /// Domains that always go through the fallback set.
    #[serde(default)]
    pub domain: Vec<String>,
}

impl Default for FallbackFilterConfig {
    fn default() -> Self {
        Self {
            geoip: true,
            geoip_code: default_geoip_code(),
            ipcidr: Vec::new(),
            domain: Vec::new(),
        }
    }
}

fn default_geoip_code() -> String {
    "CN".to_string()
}

fn default_enabled_true() -> bool {
    true
}

fn default_fake_ip_range() -> String {
    // The host-address spelling (`198.18.0.1/16` rather than `198.18.0.0/16`),
    // which is what profiles carry. The pool is derived from the network address
    // either way, so both describe the same range — but echoing the range the
    // profile named leaves one less difference to reconcile during a config
    // round-trip.
    "198.18.0.1/16".to_string()
}

fn default_fake_ip_ttl() -> u32 {
    10
}

fn default_dns_cache_size() -> usize {
    4096
}

/// DNS configuration.
///
/// Keys are kebab-case, the spelling every profile in the wild uses, with the
/// underscore spelling accepted as an alias so profiles written against earlier
/// versions of this engine keep working.
///
/// Every field here is read by something. That is a deliberate constraint: a
/// DNS setting that parses and is then ignored is worse than one that is
/// rejected, because the operator has no way to tell the difference and will
/// debug the wrong layer.
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    /// Enable the DNS section.
    #[serde(default)]
    pub enable: bool,

    /// Address the client-facing DNS server listens on.
    #[serde(default = "default_dns_listen")]
    pub listen: String,

    /// Upstream resolvers, tried in order.
    #[serde(default = "default_dns_nameservers")]
    pub nameservers: Vec<String>,

    /// Resolvers used for an answer the filter rejects; see
    /// [`FallbackFilterConfig`].
    ///
    /// Empty by default, and deliberately not seeded the way `nameservers` is.
    /// A fallback list is what arms the bogus-address signal, so seeding it
    /// would re-resolve every answer that happens to be private or reserved —
    /// including a proxy node that legitimately lives at a LAN address. An
    /// operator who wants that behaviour names the servers; a default must not
    /// decide it for them.
    #[serde(default)]
    pub fallback: Vec<String>,

    /// Resolvers used only to resolve a resolver's own hostname.
    ///
    /// A `doh://` or `dot://` upstream is a hostname, and resolving that
    /// hostname through the very server it names is circular. This set breaks
    /// the loop. When it is empty, the plain-address upstreams from
    /// `nameservers` are used; when there are none of those either, the system
    /// resolver is the last resort.
    #[serde(default, alias = "default_nameserver")]
    pub default_nameserver: Vec<String>,

    /// Resolution mode.
    #[serde(default, alias = "enhanced_mode")]
    pub enhanced_mode: DnsMode,

    /// Per-suffix resolver overrides (`nameserver-policy`): keys like
    /// `+.example.com`, values are upstream server strings. Applies to the
    /// engine's own outbound server names (node domains).
    #[serde(default, alias = "nameserver_policy")]
    pub nameserver_policy: std::collections::HashMap<String, Vec<String>>,

    /// When to re-resolve through `fallback`.
    #[serde(default, alias = "fallback_filter")]
    pub fallback_filter: FallbackFilterConfig,

    /// Address pool handed out in fake-IP mode, in CIDR form.
    #[serde(default = "default_fake_ip_range", alias = "fake_ip_range")]
    pub fake_ip_range: String,

    /// Suffixes that must never receive a fake address, because the client
    /// needs the real one to reach them.
    #[serde(default, alias = "fake_ip_filter")]
    pub fake_ip_filter: Vec<String>,

    /// TTL handed to the client for a fake address, in seconds.
    ///
    /// The mapping behind a fake address lives only in this process, so this
    /// bounds how long a client can keep dialling an address that may no longer
    /// be mapped. Ten seconds is short on purpose: a longer TTL widens exactly
    /// that window, and nothing is gained by widening it.
    #[serde(default = "default_fake_ip_ttl", alias = "fake_ip_ttl")]
    pub fake_ip_ttl: u32,

    /// Static host entries, answered without asking anyone.
    #[serde(default)]
    pub hosts: std::collections::HashMap<String, String>,

    /// Whether `hosts` is consulted at all.
    #[serde(default = "default_enabled_true", alias = "use_hosts")]
    pub use_hosts: bool,

    /// Entries the resolver's forward cache may hold.
    #[serde(default = "default_dns_cache_size", alias = "cache_size")]
    pub cache_size: usize,
}

impl DnsConfig {
    /// The resolver's view of this section.
    ///
    /// Built here rather than in the resolver so the dependency runs one way:
    /// the engine knows about DNS, DNS does not know about engine config.
    pub fn resolver_settings(&self) -> crate::dns::engine_resolver::EngineDnsSettings {
        crate::dns::engine_resolver::EngineDnsSettings {
            nameservers: self.nameservers.clone(),
            fallback: self.fallback.clone(),
            default_nameserver: self.default_nameserver.clone(),
            policy: self.nameserver_policy.clone(),
            // Only IP literals are usable here; a name-to-name alias is legal
            // in this dialect but this build does not implement one. The caller
            // warns about what it drops rather than dropping it quietly.
            hosts: self
                .hosts
                .iter()
                .filter_map(|(host, address)| {
                    address
                        .trim()
                        .parse::<std::net::IpAddr>()
                        .ok()
                        .map(|ip| (host.clone(), ip))
                })
                .collect(),
            cache_size: self.cache_size,
            geoip: self.fallback_filter.geoip,
            geoip_code: self.fallback_filter.geoip_code.clone(),
            fallback_ipcidr: self.fallback_filter.ipcidr.clone(),
            fallback_domain: self.fallback_filter.domain.clone(),
        }
    }

    /// The fake-IP pool as a network, when it parses.
    ///
    /// Returns `Err` with the offending text so validation can name it rather
    /// than silently falling back to a default pool the operator never asked
    /// for.
    pub fn fake_ip_network(&self) -> std::result::Result<ipnet::IpNet, String> {
        self.fake_ip_range
            .trim()
            .parse::<ipnet::IpNet>()
            .map_err(|error| format!("invalid fake-ip-range '{}': {error}", self.fake_ip_range))
    }

    /// Look up a static host entry, folding ASCII case the way DNS does.
    pub fn host_entry(&self, name: &str) -> Option<&str> {
        if !self.use_hosts {
            return None;
        }
        let wanted = name.trim_end_matches('.');
        self.hosts
            .iter()
            .find(|(host, _)| host.trim_end_matches('.').eq_ignore_ascii_case(wanted))
            .map(|(_, address)| address.as_str())
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: default_dns_listen(),
            nameservers: default_dns_nameservers(),
            fallback: Vec::new(),
            default_nameserver: Vec::new(),
            enhanced_mode: DnsMode::default(),
            nameserver_policy: std::collections::HashMap::new(),
            fallback_filter: FallbackFilterConfig::default(),
            fake_ip_range: default_fake_ip_range(),
            fake_ip_filter: Vec::new(),
            fake_ip_ttl: default_fake_ip_ttl(),
            hosts: std::collections::HashMap::new(),
            use_hosts: true,
            cache_size: default_dns_cache_size(),
        }
    }
}

/// Inbound configuration
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct InboundConfig {
    /// Inbound type
    #[serde(rename = "type")]
    pub inbound_type: InboundType,

    /// Tag for routing
    pub tag: String,

    /// Listening address
    #[serde(default = "default_bind_address")]
    pub listen: String,

    /// Listening port
    pub port: u16,

    /// Protocol-specific options
    #[serde(flatten)]
    pub options: HashMap<String, nextjson::Value>,
}

/// Outbound configuration
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct OutboundConfig {
    /// Outbound type
    #[serde(rename = "type")]
    pub outbound_type: OutboundType,

    /// Tag for routing
    pub tag: String,

    /// Server address
    pub server: Option<String>,

    /// Server port
    pub port: Option<u16>,

    /// Protocol-specific options
    #[serde(flatten)]
    pub options: HashMap<String, nextjson::Value>,
}

/// Routing rule configuration
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct RuleConfig {
    /// Rule type
    #[serde(rename = "type")]
    pub rule_type: RuleType,

    /// Payload (match pattern). Empty for the logical combinators, whose
    /// condition lives in [`RuleConfig::rules`].
    #[serde(default)]
    pub payload: String,

    /// Target outbound tag
    pub outbound: String,

    /// Process name (legacy single-purpose field kept for older profiles;
    /// `process-name` rules read their pattern from `payload`)
    #[serde(default)]
    pub process_name: Option<String>,

    /// `no-resolve`: forbid this rule from seeing an address obtained by
    /// resolving the destination domain.
    ///
    /// Without it an `ip-cidr` rule matches both a literal destination address
    /// and one the router looked up, which is why every IP rule used to force a
    /// DNS query. With it the rule only ever compares against an address the
    /// client actually supplied, and the router skips the lookup entirely when
    /// every IP rule is marked this way.
    #[serde(default)]
    pub no_resolve: bool,

    /// Child rules for `and` / `or` / `not`.
    ///
    /// Decoded on demand rather than typed as `Vec<RuleConfig>`: the derived
    /// schema constant of a type that contains itself is self-referential, and
    /// the compiler rejects that cycle outright. The router decodes one level
    /// at a time while compiling, so nesting depth stays unbounded while the
    /// config structure stays flat.
    #[serde(default)]
    pub rules: Vec<nextjson::Value>,
}

/// Placeholder values for programmatic construction.
///
/// Every field that has no meaningful default is rejected by
/// [`config::validator`](crate::engine::config::validator) when it is left
/// empty, so a `Default` rule can never reach the router unnoticed.
impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            rule_type: RuleType::Domain,
            payload: String::new(),
            outbound: String::new(),
            process_name: None,
            no_resolve: false,
            rules: Vec::new(),
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct AuthenticationConfig {
    pub username: String,
    pub password: String,
}

/// Proxy mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl_config_enum!(Mode {
    Rule => "rule",
    Global => "global",
    Direct => "direct",
});

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    #[default]
    Info,
    Warning,
    Error,
    Debug,
    Silent,
}

impl_config_enum!(LogLevel {
    Info => "info",
    Warning => "warning" | "warn",
    Error => "error",
    Debug => "debug",
    Silent => "silent",
});

/// DNS mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsMode {
    #[default]
    Normal,
    FakeIp,
}

impl_config_enum!(DnsMode {
    Normal => "normal",
    FakeIp => "fake-ip" | "fakeip" | "fake_ip",
});

/// Inbound protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundType {
    Http,
    Socks5,
    Mixed,
    Redir,
    Tproxy,
    Tun,
}

impl_config_enum!(InboundType {
    Http => "http",
    Socks5 => "socks5" | "socks",
    Mixed => "mixed",
    Redir => "redir",
    Tproxy => "tproxy",
    Tun => "tun",
});

/// Outbound protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundType {
    Direct,
    Reject,
    Shadowsocks,
    ShadowsocksR,
    Snell,
    Vmess,
    Vless,
    Trojan,
    Wireguard,
    Tuic,
    Hysteria,
    Hysteria2,
    ShadowTls,
    Naive,
    Socks5,
    Socks4,
    Http,
    // Proxy group types
    Selector,
    Urltest,
    Fallback,
    Loadbalance,
    Relay,
}

impl_config_enum!(OutboundType {
    Direct => "direct",
    Reject => "reject",
    Shadowsocks => "shadowsocks" | "ss",
    ShadowsocksR => "shadowsocksr" | "ssr",
    Snell => "snell",
    Vmess => "vmess",
    Vless => "vless",
    Trojan => "trojan",
    Wireguard => "wireguard",
    Tuic => "tuic",
    // `hysteria` is deliberately *not* an alias of `hysteria2`: the two are
    // different protocols, and a profile that says `hysteria` means v1.
    Hysteria => "hysteria" | "hysteria1" | "hy1",
    Hysteria2 => "hysteria2" | "hy2",
    ShadowTls => "shadowtls" | "shadow-tls",
    // `naive+https` is the spelling sing-box uses for the same client: the
    // tunnel is HTTPS-only, so the two names mean one thing here.
    Naive => "naive" | "naiveproxy" | "naive-proxy" | "naive+https",
    Socks5 => "socks5" | "socks",
    // `socks4a` names the same outbound: the dialect is chosen per target
    // (`version` in the options pins it when a server needs the 4 form).
    Socks4 => "socks4" | "socks4a" | "socks4-a",
    Http => "http",
    Selector => "selector" | "select",
    Urltest => "url-test" | "urltest",
    Fallback => "fallback",
    Loadbalance => "load-balance" | "loadbalance",
    Relay => "relay",
});

impl OutboundType {
    /// Whether this is a policy *over* outbounds rather than a way out of the
    /// machine.
    ///
    /// A group has no server and dials nothing of its own, so anything asking
    /// "is this a proxy?" has to ask this first — and the answer is one list,
    /// not one match per caller.
    pub const fn is_group(self) -> bool {
        matches!(
            self,
            Self::Selector | Self::Urltest | Self::Fallback | Self::Loadbalance | Self::Relay
        )
    }

    /// The cargo feature this build would have needed for the outbound to be
    /// constructible: `Some(feature)` when the protocol was **not** compiled
    /// in, `None` when it is available.
    ///
    /// Both config validation and the outbound factory consult this, so a
    /// config naming a disabled protocol fails closed with one actionable
    /// message instead of degrading to a direct connection.
    pub const fn disabled_feature(self) -> Option<&'static str> {
        match self {
            OutboundType::Wireguard if !cfg!(feature = "wireguard") => Some("wireguard"),
            OutboundType::Tuic if !cfg!(feature = "tuic") => Some("tuic"),
            OutboundType::Hysteria if !cfg!(feature = "hysteria") => Some("hysteria"),
            OutboundType::Hysteria2 if !cfg!(feature = "hysteria2") => Some("hysteria2"),
            OutboundType::ShadowTls if !cfg!(feature = "shadowtls") => Some("shadowtls"),
            _ => None,
        }
    }
}

/// Error for a config that names a protocol this build disabled. `feature` is
/// the cargo feature that turns it on (see [`OutboundType::disabled_feature`]).
pub(crate) fn disabled_protocol_error(tag: &str, feature: &str) -> crate::engine::error::Error {
    crate::engine::error::Error::config(format!(
        "Outbound '{tag}' requires the `{feature}` cargo feature, which this build \
         disabled; rebuild with `--features {feature}`"
    ))
}

/// Rule types
///
/// Spelling follows the vocabulary the profiles this engine consumes are
/// written in; aliases accept the underscore form that hand-written configs and
/// proxy tools commonly use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    Geoip,
    IpCidr,
    SrcIpCidr,
    SrcPort,
    DstPort,
    ProcessName,
    ProcessPath,
    Network,
    RuleSet,
    Geosite,
    And,
    Or,
    Not,
    Match,
}

impl_config_enum!(RuleType {
    Domain => "domain",
    DomainSuffix => "domain-suffix" | "domain_suffix",
    DomainKeyword => "domain-keyword" | "domain_keyword",
    DomainRegex => "domain-regex" | "domain_regex",
    Geoip => "geoip",
    IpCidr => "ip-cidr" | "ip_cidr" | "ip-cidr6" | "ip_cidr6",
    SrcIpCidr => "src-ip-cidr" | "src_ip_cidr",
    SrcPort => "src-port" | "src_port",
    DstPort => "dst-port" | "dst_port",
    ProcessName => "process-name" | "process_name",
    ProcessPath => "process-path" | "process_path",
    Network => "network",
    RuleSet => "rule-set" | "rule_set",
    Geosite => "geosite",
    And => "and",
    Or => "or",
    Not => "not",
    Match => "match",
});

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_dns_nameservers() -> Vec<String> {
    vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
}

fn default_dns_listen() -> String {
    "127.0.0.1:53".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compatibility contract for the DNS section.
    ///
    /// Profiles write kebab-case, the Flutter layer builds snake_case, and both
    /// have to land on the same field. A one-sided rename here
    /// silently stops the app's DNS settings from applying at all, which is
    /// the failure this test exists to prevent.
    #[test]
    fn dns_keys_accept_both_spellings() {
        let kebab: DnsConfig = nextjson::from_str(
            r#"{"enable":true,"enhanced-mode":"fake-ip",
                "nameserver-policy":{"+.a.com":["1.1.1.1"]},
                "fake-ip-range":"198.19.0.0/16","cache-size":99,
                "default-nameserver":["223.5.5.5"],"use-hosts":false}"#,
        )
        .expect("kebab-case DNS config");

        let snake: DnsConfig = nextjson::from_str(
            r#"{"enable":true,"enhanced_mode":"fake-ip",
                "nameserver_policy":{"+.a.com":["1.1.1.1"]},
                "fake_ip_range":"198.19.0.0/16","cache_size":99,
                "default_nameserver":["223.5.5.5"],"use_hosts":false}"#,
        )
        .expect("snake_case DNS config");

        assert_eq!(kebab.enhanced_mode, snake.enhanced_mode);
        assert_eq!(kebab.nameserver_policy, snake.nameserver_policy);
        assert_eq!(kebab.use_hosts, snake.use_hosts);
        assert_eq!(kebab.cache_size, snake.cache_size);
        assert_eq!(kebab.default_nameserver, snake.default_nameserver);

        // Values, not just equality: a `default` that fired on both sides would
        // make the assertions above pass while nothing was parsed.
        assert_eq!(kebab.enhanced_mode, DnsMode::FakeIp);
        assert_eq!(kebab.fake_ip_range, "198.19.0.0/16");
        assert_eq!(kebab.cache_size, 99);
        assert!(!kebab.use_hosts);
        assert_eq!(kebab.nameserver_policy["+.a.com"], vec!["1.1.1.1"]);
    }

    /// A field the caller never mentions keeps the engine default instead of
    /// being flattened to the zero value.
    ///
    /// `fallback` is the exception that proves the rule: it stays empty, because
    /// a fallback list arms the bogus-address signal and a default must not arm
    /// it for a profile whose proxy node sits on a private address.
    #[test]
    fn absent_dns_keys_keep_their_defaults() {
        let partial: DnsConfig =
            nextjson::from_str(r#"{"enable":true}"#).expect("minimal DNS config");
        let default = DnsConfig::default();
        assert_eq!(partial.nameservers, default.nameservers);
        assert_eq!(partial.nameservers, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(partial.fake_ip_range, default.fake_ip_range);
        assert_eq!(partial.fake_ip_range, "198.18.0.1/16");
        assert_eq!(partial.cache_size, default.cache_size);
        assert!(partial.use_hosts);

        assert!(partial.fallback.is_empty());
        assert_eq!(partial.fallback, default.fallback);
    }

    /// The default range's host-address spelling has to resolve to the same
    /// network rather than being rejected; garbage has to name itself, because a
    /// silent fall back to a default pool the operator never asked for is worse
    /// than a refusal to start.
    #[test]
    fn fake_ip_range_must_be_a_cidr() {
        let valid = DnsConfig {
            fake_ip_range: "198.18.0.0/16".to_string(),
            ..DnsConfig::default()
        };
        assert!(valid.fake_ip_network().is_ok());

        let host_address_spelling = DnsConfig {
            fake_ip_range: "198.18.0.1/16".to_string(),
            ..DnsConfig::default()
        };
        let network = host_address_spelling.fake_ip_network().expect("parses");
        assert_eq!(network.prefix_len(), 16);
        // The pool starts three addresses into the range, so this is the first
        // address the client can actually be handed.
        assert!(
            network.contains(&"198.18.0.3".parse::<std::net::IpAddr>().expect("ip")),
            "the derived network must contain the first allocation"
        );

        let invalid = DnsConfig {
            fake_ip_range: "not-a-cidr".to_string(),
            ..DnsConfig::default()
        };
        let error = invalid
            .fake_ip_network()
            .expect_err("garbage must be rejected");
        assert!(
            error.contains("not-a-cidr"),
            "message must name the value: {error}"
        );
    }

    /// Every configuration enum has two string readers: the one the
    /// deserializer uses and [`impl_config_enum`]'s `parse`. Both are generated
    /// from a single list, and this is what keeps that true — a spelling that
    /// reached one table but not the other would be a value that loads from a
    /// profile but cannot be set at runtime, or the reverse.
    #[test]
    fn the_two_string_readers_agree_on_every_spelling() {
        for spelling in ["silent", "error", "warning", "warn", "info", "debug"] {
            let decoded: LogLevel = nextjson::from_str(&format!("\"{spelling}\""))
                .unwrap_or_else(|e| panic!("`{spelling}` must decode: {e}"));
            assert_eq!(LogLevel::parse(spelling), Some(decoded), "`{spelling}`");
        }
        assert_eq!(LogLevel::parse("trace"), None, "not part of the vocabulary");
        assert_eq!(
            LogLevel::parse("Info"),
            None,
            "parse is exact; callers normalise"
        );

        for spelling in ["rule", "global", "direct"] {
            let decoded: Mode =
                nextjson::from_str(&format!("\"{spelling}\"")).expect("a known mode");
            assert_eq!(Mode::parse(spelling), Some(decoded), "`{spelling}`");
        }
        assert_eq!(Mode::parse("bypass"), None);

        // Aliases are the interesting half: they exist so that hand-written
        // configs keep loading, and they have to appear in both readers.
        for spelling in [
            "domain-suffix",
            "domain_suffix",
            "ip-cidr",
            "ip_cidr",
            "rule-set",
            "rule_set",
        ] {
            let decoded: RuleType =
                nextjson::from_str(&format!("\"{spelling}\"")).expect("a known rule type");
            assert_eq!(RuleType::parse(spelling), Some(decoded), "`{spelling}`");
        }
        assert_eq!(RuleType::parse("domain_suffixes"), None);
    }

    /// Group detection and the spellings the DTOs print.
    ///
    /// Both used to be decided per call site — one as a five-arm `match` that
    /// returned `Option`, one as `format!("{:?}")` — and the two answers
    /// disagreed: the debug form spells the same group `urltest` where every
    /// profile and every other DTO says `url-test`.
    #[test]
    fn group_types_are_recognised_and_spelled_the_way_profiles_write_them() {
        for group in [
            OutboundType::Selector,
            OutboundType::Urltest,
            OutboundType::Fallback,
            OutboundType::Loadbalance,
            OutboundType::Relay,
        ] {
            assert!(group.is_group(), "{group:?} is a policy over outbounds");
        }
        for proxy in [
            OutboundType::Direct,
            OutboundType::Reject,
            OutboundType::Shadowsocks,
            OutboundType::Vmess,
            OutboundType::Socks5,
        ] {
            assert!(!proxy.is_group(), "{proxy:?} dials a server of its own");
        }

        assert_eq!(OutboundType::Urltest.as_str(), "url-test");
        assert_eq!(OutboundType::Loadbalance.as_str(), "load-balance");
        assert_eq!(OutboundType::ShadowTls.as_str(), "shadowtls");
        assert_eq!(RuleType::DomainSuffix.as_str(), "domain-suffix");
        assert_eq!(RuleType::RuleSet.as_str(), "rule-set");
    }
}
