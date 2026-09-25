use nextjson::{NsonDeserialize, NsonSerialize};

#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct CorduitConfig {
    /// General settings
    pub general: GeneralConfig,

    /// DNS configuration
    pub dns: DnsConfig,

    /// Inbound configurations
    pub inbounds: Vec<InboundConfig>,

    /// Outbound configurations
    pub outbounds: Vec<OutboundConfig>,

    /// Routing rules
    pub rules: Vec<RuleConfig>,
}

/// General configuration for FFI
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct GeneralConfig {
    pub socks_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub authentication: Option<Vec<AuthenticationConfig>>,
    pub allow_lan: bool,
    pub bind_address: String,
    pub mode: String,
    pub log_level: String,
    pub ipv6: bool,
    pub tcp_concurrent: bool,
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub secret: Option<String>,
}

/// DNS configuration for FFI
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct DnsConfig {
    pub enable: bool,
    pub listen: String,
    pub nameservers: Vec<String>,
    pub fallback: Vec<String>,
    pub enhanced_mode: String,
    #[serde(default)]
    pub nameserver_policy: std::collections::HashMap<String, Vec<String>>,
    /// Resolvers used only to resolve a resolver's own hostname.
    #[serde(default)]
    pub default_nameserver: Vec<String>,
    /// When an answer is suspect enough to re-resolve through `fallback`.
    #[serde(default)]
    pub fallback_filter: Option<DnsFallbackFilterDto>,
    /// Fake-IP pool in CIDR form. `None` keeps the engine default rather than
    /// replacing it with an empty string.
    #[serde(default)]
    pub fake_ip_range: Option<String>,
    /// Suffixes that must never receive a fake address.
    #[serde(default)]
    pub fake_ip_filter: Vec<String>,
    /// TTL handed to the client for a fake address. `None` keeps the engine
    /// default rather than replacing it with zero.
    #[serde(default)]
    pub fake_ip_ttl: Option<u32>,
    /// Static host entries.
    #[serde(default)]
    pub hosts: std::collections::HashMap<String, String>,
    /// Whether `hosts` is consulted. `None` keeps the engine default.
    #[serde(default)]
    pub use_hosts: Option<bool>,
    /// Forward-cache capacity. `None` keeps the engine default.
    #[serde(default)]
    pub cache_size: Option<usize>,
}

/// `fallback-filter` for FFI.
#[derive(Debug, Clone, Default, NsonSerialize, NsonDeserialize)]
pub struct DnsFallbackFilterDto {
    #[serde(default)]
    pub geoip: Option<bool>,
    #[serde(default)]
    pub geoip_code: Option<String>,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
}

/// Inbound configuration for FFI
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct InboundConfig {
    pub inbound_type: String,
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub options: String, // JSON string for complex options
}

/// Outbound configuration for FFI
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct OutboundConfig {
    pub outbound_type: String,
    pub tag: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub options: String, // JSON string for complex options
}

/// Routing rule configuration for FFI
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct RuleConfig {
    pub rule_type: String,
    /// Match pattern. Empty for the logical combinators.
    #[serde(default)]
    pub payload: String,
    pub outbound: String,
    #[serde(default)]
    pub process_name: Option<String>,
    /// `no-resolve` modifier, carried through to the engine unchanged.
    #[serde(default)]
    pub no_resolve: bool,
    /// Child rules for `and` / `or` / `not`, carried through as untyped values
    /// so nesting depth is not fixed by this DTO.
    #[serde(default)]
    pub rules: Vec<nextjson::Value>,
}

/// Authentication configuration for FFI
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct AuthenticationConfig {
    pub username: String,
    pub password: String,
}

/// Proxy status information
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub inbound_count: u32,
    pub outbound_count: u32,
    pub connection_count: u32,
    pub memory_usage: u64,
    pub uptime: u64,
}

/// Traffic statistics
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct TrafficStats {
    pub upload: u64,
    pub download: u64,
    pub upload_speed: u64,
    pub download_speed: u64,
}

/// Connection information
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub host: String,
    pub destination: String,
    pub upload: u64,
    pub download: u64,
    pub start_time: u64,
    pub rule: String,
    pub chains: Vec<String>,
}

/// System information
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct SystemInfo {
    pub platform: String,
    pub version: String,
    pub memory_total: u64,
    pub memory_used: u64,
    pub cpu_cores: u32,
    pub cpu_threads: u32,
    pub cpu_name: String,
    pub cpu_usage: f64,
}

/// Latency test result
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct LatencyTestResult {
    pub proxy_name: String,
    pub latency_ms: Option<u32>,
    pub success: bool,
    pub error: Option<String>,
}

/// Local JSON-RPC server status (never exposes the token itself).
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct RpcServerStatus {
    /// Whether the server's accept loop is running.
    pub running: bool,
    /// The bound address, e.g. `"127.0.0.1:8000"` (`None` when stopped).
    pub addr: Option<String>,
    /// Whether a bearer token is required (always `true` while running).
    pub token_set: bool,
}

/// External controller status (never exposes the secret).
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ExternalControllerStatus {
    /// Whether the controller's accept loop is running.
    pub running: bool,
    /// The bound address, e.g. `"127.0.0.1:9090"` (`None` when stopped).
    pub addr: Option<String>,
    /// Whether requests must present `general.secret`.
    pub secret_required: bool,
}

/// Active connection for tracking
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ActiveConnection {
    pub id: String,
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub host: String,
    pub destination_ip: Option<String>,
    pub destination_port: u16,
    pub protocol: String,
    pub network: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub start_time: u64,
    pub rule: String,
    pub rule_payload: String,
    pub process_name: Option<String>,
}

/// TUN mode status
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct TunStatus {
    pub enabled: bool,
    pub interface_name: Option<String>,
    pub mtu: Option<u32>,
    pub error: Option<String>,
}

// ============== QUIC Proxy Types ==============

/// QUIC proxy configuration for FFI
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct QuicProxyConfig {
    /// Server address (host:port)
    pub server: String,
    /// Server port
    pub port: u16,
    /// Password for authentication
    pub password: String,
    /// Cipher type (aes-256-gcm, chacha20-poly1305, etc.)
    pub cipher: String,
    /// SNI server name for camouflage
    pub server_name: Option<String>,
    /// ALPN protocols
    pub alpn: Option<Vec<String>>,
    /// Skip certificate verification
    pub skip_cert_verify: bool,
    /// Enable 0-RTT
    pub zero_rtt: bool,
    /// Enable UDP relay
    pub udp_relay: bool,
    /// Congestion control (cubic, bbr, newreno)
    pub congestion_control: Option<String>,
    /// Idle timeout in seconds
    pub idle_timeout: Option<u32>,
}

/// QUIC connection status
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct QuicConnectionStatus {
    pub connected: bool,
    pub server: String,
    pub rtt_ms: Option<u32>,
    pub zero_rtt_accepted: bool,
    pub streams_count: u32,
    pub error: Option<String>,
}

// ============== Design Document Compliant DTO Types ==============

/// Traffic statistics DTO (Design Document Compliant)
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct TrafficStatsDto {
    pub upload: u64,
    pub download: u64,
    pub total_upload: u64,
    pub total_download: u64,
    pub connection_count: u32,
    pub uptime_secs: u64,
}

/// Connection DTO (Design Document Compliant)
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ConnectionDto {
    pub id: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub dst_domain: Option<String>,
    pub protocol: String,
    pub outbound: String,
    pub upload: u64,
    pub download: u64,
    pub start_time: i64,
    pub rule: Option<String>,
}

/// Proxy info DTO (Design Document Compliant)
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ProxyInfoDto {
    pub tag: String,
    pub protocol_type: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub latency_ms: Option<u64>,
    pub alive: bool,
}

/// Proxy group DTO (Design Document Compliant)
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ProxyGroupDto {
    pub tag: String,
    pub group_type: String,
    pub proxies: Vec<String>,
    pub selected: String,
}

/// Proxy latency DTO (Design Document Compliant)
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ProxyLatencyDto {
    pub tag: String,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Rule DTO (Design Document Compliant)
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct RuleDto {
    pub rule_type: String,
    pub payload: String,
    pub outbound: String,
    pub matched_count: u64,
}

/// DNS config DTO (Design Document Compliant)
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct DnsConfigDto {
    pub enable: bool,
    pub listen: String,
    pub enhanced_mode: String,
    pub nameservers: Vec<String>,
    pub fallback: Vec<String>,
    #[serde(default)]
    pub nameserver_policy: std::collections::HashMap<String, Vec<String>>,
    #[serde(default)]
    pub default_nameserver: Vec<String>,
    #[serde(default)]
    pub fallback_filter: DnsFallbackFilterDto,
    #[serde(default)]
    pub fake_ip_range: String,
    #[serde(default)]
    pub fake_ip_filter: Vec<String>,
    #[serde(default)]
    pub fake_ip_ttl: u32,
    /// Number of static host entries in effect. The entries themselves are not
    /// exported: a UI only needs the count, and a hosts file can be large.
    #[serde(default)]
    pub host_count: usize,
    #[serde(default)]
    pub use_hosts: bool,
    #[serde(default)]
    pub cache_size: usize,
}

// ============== From Trait Implementations for DTO Types ==============

impl TrafficStatsDto {
    /// Create a new TrafficStatsDto with default values
    pub fn new() -> Self {
        Self {
            upload: 0,
            download: 0,
            total_upload: 0,
            total_download: 0,
            connection_count: 0,
            uptime_secs: 0,
        }
    }

    /// Create from upload/download values
    pub fn from_traffic(
        upload: u64,
        download: u64,
        connection_count: u32,
        uptime_secs: u64,
    ) -> Self {
        Self {
            upload,
            download,
            total_upload: upload,
            total_download: download,
            connection_count,
            uptime_secs,
        }
    }
}

impl Default for TrafficStatsDto {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionDto {
    /// Create a new ConnectionDto
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        src_addr: String,
        dst_addr: String,
        dst_domain: Option<String>,
        protocol: String,
        outbound: String,
        upload: u64,
        download: u64,
        start_time: i64,
        rule: Option<String>,
    ) -> Self {
        Self {
            id,
            src_addr,
            dst_addr,
            dst_domain,
            protocol,
            outbound,
            upload,
            download,
            start_time,
            rule,
        }
    }
}

impl ProxyInfoDto {
    /// Create a new ProxyInfoDto
    pub fn new(
        tag: String,
        protocol_type: String,
        server: Option<String>,
        port: Option<u16>,
    ) -> Self {
        Self {
            tag,
            protocol_type,
            server,
            port,
            latency_ms: None,
            alive: true,
        }
    }

    /// Set latency
    pub fn with_latency(mut self, latency_ms: Option<u64>) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    /// Set alive status
    pub fn with_alive(mut self, alive: bool) -> Self {
        self.alive = alive;
        self
    }
}

impl ProxyGroupDto {
    /// Create a new ProxyGroupDto
    pub fn new(tag: String, group_type: String, proxies: Vec<String>, selected: String) -> Self {
        Self {
            tag,
            group_type,
            proxies,
            selected,
        }
    }
}

impl ProxyLatencyDto {
    /// Create a successful latency result
    pub fn success(tag: String, latency_ms: u64) -> Self {
        Self {
            tag,
            latency_ms: Some(latency_ms),
            error: None,
        }
    }

    /// Create a failed latency result
    pub fn failure(tag: String, error: String) -> Self {
        Self {
            tag,
            latency_ms: None,
            error: Some(error),
        }
    }
}

impl RuleDto {
    /// Create a new RuleDto
    pub fn new(rule_type: String, payload: String, outbound: String) -> Self {
        Self {
            rule_type,
            payload,
            outbound,
            matched_count: 0,
        }
    }

    /// Set matched count
    pub fn with_matched_count(mut self, count: u64) -> Self {
        self.matched_count = count;
        self
    }
}

impl DnsConfigDto {
    /// Create a new DnsConfigDto
    pub fn new(
        enable: bool,
        listen: String,
        enhanced_mode: String,
        nameservers: Vec<String>,
        fallback: Vec<String>,
    ) -> Self {
        Self {
            enable,
            listen,
            enhanced_mode,
            nameservers,
            fallback,
            nameserver_policy: std::collections::HashMap::new(),
            default_nameserver: Vec::new(),
            fallback_filter: DnsFallbackFilterDto::default(),
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter: Vec::new(),
            fake_ip_ttl: 10,
            host_count: 0,
            use_hosts: true,
            cache_size: 4096,
        }
    }
}

impl Default for DnsConfigDto {
    fn default() -> Self {
        Self {
            enable: false,
            listen: "127.0.0.1:53".to_string(),
            enhanced_mode: "redir-host".to_string(),
            nameservers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            fallback: Vec::new(),
            nameserver_policy: std::collections::HashMap::new(),
            default_nameserver: Vec::new(),
            fallback_filter: DnsFallbackFilterDto::default(),
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter: Vec::new(),
            fake_ip_ttl: 10,
            host_count: 0,
            use_hosts: true,
            cache_size: 4096,
        }
    }
}

// ============== Conversion from corduit-core types ==============

/// Convert from TrackedConnection to ConnectionDto
impl ConnectionDto {
    /// Create from a TrackedConnection reference
    pub fn from_tracked_connection(
        conn: &crate::engine::connection_tracker::TrackedConnection,
    ) -> Self {
        Self {
            id: conn.id.clone(),
            src_addr: format!("{}:{}", conn.host, conn.destination_port),
            dst_addr: conn.destination_ip.clone().unwrap_or_default(),
            dst_domain: Some(conn.host.clone()),
            protocol: conn.protocol.clone(),
            outbound: conn.outbound_tag.clone(),
            upload: conn.get_upload(),
            download: conn.get_download(),
            start_time: conn.start_timestamp as i64,
            rule: Some(conn.rule.clone()),
        }
    }
}

/// Convert from OutboundConfig to ProxyInfoDto
impl ProxyInfoDto {
    /// Create from an OutboundConfig reference
    pub fn from_outbound_config(config: &crate::engine::OutboundConfig) -> Self {
        Self {
            tag: config.tag.clone(),
            // `as_str()`, not `format!("{:?}")`: the debug form spells
            // `Urltest` as `urltest`, which is not the spelling the rest of the
            // system prints for the same group.
            protocol_type: config.outbound_type.as_str().to_string(),
            server: config.server.clone(),
            port: config.port,
            latency_ms: None,
            alive: true,
        }
    }
}

/// Convert from OutboundConfig to ProxyGroupDto (for group types)
impl ProxyGroupDto {
    /// Create from an OutboundConfig reference (for group types only)
    pub fn from_outbound_config(config: &crate::engine::OutboundConfig) -> Option<Self> {
        // A group is the one case where the same configuration type means a
        // policy rather than a proxy, so the check has to come first.
        if !config.outbound_type.is_group() {
            return None;
        }

        // Get proxies list from options
        let proxies: Vec<String> = config
            .options
            .get("proxies")
            .and_then(|v| v.as_array())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Get selected proxy (first one by default)
        let selected = proxies.first().cloned().unwrap_or_default();

        Some(Self {
            tag: config.tag.clone(),
            group_type: config.outbound_type.as_str().to_string(),
            proxies,
            selected,
        })
    }
}

/// Convert from RuleConfig to RuleDto
impl RuleDto {
    /// Create from a RuleConfig reference
    pub fn from_rule_config(config: &crate::engine::RuleConfig) -> Self {
        Self {
            rule_type: config.rule_type.as_str().to_string(),
            payload: config.payload.clone(),
            outbound: config.outbound.clone(),
            matched_count: 0, // Matched count is tracked separately
        }
    }
}

/// Convert from DnsConfig to DnsConfigDto
impl DnsConfigDto {
    /// Create from a DnsConfig reference
    pub fn from_dns_config(config: &crate::engine::DnsConfig) -> Self {
        Self {
            enable: config.enable,
            listen: config.listen.clone(),
            // `as_str()`, not `format!("{:?}")`: the debug form spells the mode
            // `fakeip`, which is not the spelling any profile or caller uses.
            enhanced_mode: config.enhanced_mode.as_str().to_string(),
            nameservers: config.nameservers.clone(),
            fallback: config.fallback.clone(),
            nameserver_policy: config.nameserver_policy.clone(),
            default_nameserver: config.default_nameserver.clone(),
            fallback_filter: DnsFallbackFilterDto {
                geoip: Some(config.fallback_filter.geoip),
                geoip_code: Some(config.fallback_filter.geoip_code.clone()),
                ipcidr: config.fallback_filter.ipcidr.clone(),
                domain: config.fallback_filter.domain.clone(),
            },
            fake_ip_range: config.fake_ip_range.clone(),
            fake_ip_filter: config.fake_ip_filter.clone(),
            fake_ip_ttl: config.fake_ip_ttl,
            host_count: config.hosts.len(),
            use_hosts: config.use_hosts,
            cache_size: config.cache_size,
        }
    }
}
