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
    /// Listening port for HTTP proxy
    #[serde(default = "default_port")]
    pub port: u16,

    /// Listening port for SOCKS5 proxy
    pub socks_port: Option<u16>,

    /// Listening port for redir proxy (Linux only)
    pub redir_port: Option<u16>,

    /// Listening port for TProxy (Linux only)
    pub tproxy_port: Option<u16>,

    /// Listening port for mixed proxy
    pub mixed_port: Option<u16>,

    /// Authentication settings
    pub authentication: Option<Vec<AuthenticationConfig>>,

    /// Allow LAN access
    #[serde(default)]
    pub allow_lan: bool,

    /// Bind address
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

    /// TCP concurrent connections
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
            port: default_port(),
            socks_port: None,
            redir_port: None,
            tproxy_port: None,
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

/// DNS configuration
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct DnsConfig {
    /// Enable DNS server
    #[serde(default)]
    pub enable: bool,

    /// Listen address for DNS server
    #[serde(default = "default_dns_listen")]
    pub listen: String,

    /// Default DNS nameservers
    #[serde(default)]
    pub nameservers: Vec<String>,

    /// Fallback DNS nameservers
    #[serde(default)]
    pub fallback: Vec<String>,

    /// Enhanced mode
    #[serde(default)]
    pub enhanced_mode: DnsMode,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: default_dns_listen(),
            nameservers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            fallback: vec!["8.8.4.4".to_string(), "1.0.0.1".to_string()],
            enhanced_mode: DnsMode::default(),
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

    /// Payload (match pattern)
    pub payload: String,

    /// Target outbound tag
    pub outbound: String,

    /// Process name (for PROCESS rule)
    pub process_name: Option<String>,
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
    Vmess,
    Vless,
    Trojan,
    Wireguard,
    Tuic,
    Hysteria2,
    Socks5,
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
    Vmess => "vmess",
    Vless => "vless",
    Trojan => "trojan",
    Wireguard => "wireguard",
    Tuic => "tuic",
    Hysteria2 => "hysteria2" | "hy2",
    Socks5 => "socks5" | "socks",
    Http => "http",
    Selector => "selector" | "select",
    Urltest => "url-test" | "urltest",
    Fallback => "fallback",
    Loadbalance => "load-balance" | "loadbalance",
    Relay => "relay",
});

/// Rule types
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
    RuleSet,
    Match,
}

impl_config_enum!(RuleType {
    Domain => "domain",
    DomainSuffix => "domain-suffix" | "domain_suffix",
    DomainKeyword => "domain-keyword" | "domain_keyword",
    DomainRegex => "domain-regex" | "domain_regex",
    Geoip => "geoip",
    IpCidr => "ip-cidr" | "ip_cidr",
    SrcIpCidr => "src-ip-cidr" | "src_ip_cidr",
    SrcPort => "src-port" | "src_port",
    DstPort => "dst-port" | "dst_port",
    ProcessName => "process-name" | "process_name",
    RuleSet => "rule-set" | "rule_set",
    Match => "match",
});

fn default_port() -> u16 {
    7890
}

fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_dns_listen() -> String {
    "127.0.0.1:53".to_string()
}
