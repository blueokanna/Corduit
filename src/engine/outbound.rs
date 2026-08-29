use crate::engine::config::{Config, OutboundConfig, OutboundType};
use crate::engine::error::{Error, Result};
use crate::engine::proxy_provider::{runtime_proxy_providers, ProxyProviderManager};
use parking_lot::RwLock as ParkingRwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;

mod direct;
mod http;
mod reject;
mod selector;
mod shadowsocks;
mod socks5;
mod trojan;
mod vless;
mod vmess;
mod wireguard;

pub use direct::relay_bidirectional_with_connection;
pub use direct::DirectOutbound;
pub use http::HttpOutbound;
pub use reject::RejectOutbound;
pub use selector::SelectorOutbound;
pub use shadowsocks::ShadowsocksOutbound;
pub use socks5::Socks5Outbound;
pub use trojan::TrojanOutbound;
pub use vless::VlessOutbound;
pub use vmess::VmessOutbound;
pub use wireguard::WireguardOutbound;

static GLOBAL_SELECTOR_SELECTIONS: OnceLock<ParkingRwLock<HashMap<String, String>>> =
    OnceLock::new();

pub fn get_global_selector_selections() -> &'static ParkingRwLock<HashMap<String, String>> {
    GLOBAL_SELECTOR_SELECTIONS.get_or_init(|| ParkingRwLock::new(HashMap::new()))
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Domain(String, u16),
    Ip(std::net::SocketAddr),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Domain(domain, port) => write!(f, "{}:{}", domain, port),
            TargetAddr::Ip(addr) => write!(f, "{}", addr),
        }
    }
}

impl TargetAddr {
    pub fn new_domain(domain: String, port: u16) -> Self {
        TargetAddr::Domain(domain, port)
    }

    pub fn new_ip(addr: std::net::SocketAddr) -> Self {
        TargetAddr::Ip(addr)
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, port) => *port,
            TargetAddr::Ip(addr) => addr.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            TargetAddr::Domain(domain, _) => domain.clone(),
            TargetAddr::Ip(addr) => addr.ip().to_string(),
        }
    }
}

impl From<TargetAddr> for crate::protocol::Address {
    fn from(target: TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain, port) => crate::protocol::Address::Domain(domain, port),
            TargetAddr::Ip(addr) => crate::protocol::Address::from_socket_addr(addr),
        }
    }
}

impl From<&TargetAddr> for crate::protocol::Address {
    fn from(target: &TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain, port) => {
                crate::protocol::Address::Domain(domain.clone(), *port)
            }
            TargetAddr::Ip(addr) => crate::protocol::Address::from_socket_addr(*addr),
        }
    }
}

impl From<crate::protocol::Address> for TargetAddr {
    fn from(addr: crate::protocol::Address) -> Self {
        match addr {
            crate::protocol::Address::Domain(domain, port) => TargetAddr::Domain(domain, port),
            crate::protocol::Address::Ipv4(ip, port) => TargetAddr::Ip(std::net::SocketAddr::V4(
                std::net::SocketAddrV4::new(ip, port),
            )),
            crate::protocol::Address::Ipv6(ip, port) => TargetAddr::Ip(std::net::SocketAddr::V6(
                std::net::SocketAddrV6::new(ip, port, 0, 0),
            )),
        }
    }
}

pub type ProxyRegistry = Arc<RwLock<HashMap<String, Arc<dyn OutboundProxy>>>>;

pub struct OutboundManager {
    config: Arc<RwLock<Config>>,
    proxies: ProxyRegistry,
    /// Lifecycle list (start/stop/tags); replaced atomically on reload.
    proxy_list: parking_lot::RwLock<Vec<Arc<dyn OutboundProxy>>>,
    /// Loaded `proxy-providers`; their proxies are registered in `proxies`
    /// and can be referenced by proxy groups (Clash `use:` / provider tags).
    proxy_providers: Arc<ProxyProviderManager>,
    /// Tags that came from proxy providers, so a background refresh can
    /// replace exactly those entries in the shared registry.
    provider_tags: parking_lot::RwLock<std::collections::HashSet<String>>,
}

#[async_trait::async_trait]
pub trait OutboundProxy: Send + Sync {
    async fn connect(&self) -> Result<()>;

    async fn disconnect(&self) -> Result<()>;

    fn tag(&self) -> &str;

    fn server_addr(&self) -> Option<(String, u16)> {
        None
    }

    fn supports_udp(&self) -> bool {
        false
    }

    async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: TargetAddr) -> Result<()>;

    async fn relay_tcp_with_connection(
        &self,
        inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::engine::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        let _ = connection;
        self.relay_tcp(inbound, target).await
    }

    async fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let _ = (target, data);
        Err(Error::protocol(format!(
            "UDP relay not supported by outbound '{}'",
            self.tag()
        )))
    }

    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration>;
}

/// Re-exported from `common`: the engine's canonical async duplex stream.
pub use crate::common::AsyncReadWrite;

/// Single source of truth for constructing an outbound proxy from a config.
///
/// Every outbound construction in the engine funnels through this factory so
/// adding a protocol touches exactly one place. Returns `Ok(None)` for group
/// types (Selector/Urltest/Fallback/Loadbalance/Relay), which need the shared
/// proxy registry and are resolved by the caller in a second pass. Errors on
/// unimplemented types so no caller can silently fall back to a direct
/// connection.
pub(crate) fn build_outbound_proxy(
    config: &OutboundConfig,
) -> Result<Option<Arc<dyn OutboundProxy>>> {
    let proxy: Option<Arc<dyn OutboundProxy>> = match config.outbound_type {
        OutboundType::Direct => Some(Arc::new(DirectOutbound::new(config.clone()))),
        OutboundType::Reject => Some(Arc::new(RejectOutbound::new(config.clone()))),
        OutboundType::Socks5 => Some(Arc::new(Socks5Outbound::new(config.clone())?)),
        OutboundType::Http => Some(Arc::new(HttpOutbound::new(config.clone())?)),
        OutboundType::Shadowsocks => Some(Arc::new(ShadowsocksOutbound::new(config.clone())?)),
        OutboundType::Vmess => Some(Arc::new(VmessOutbound::new(config.clone())?)),
        OutboundType::Vless => Some(Arc::new(VlessOutbound::new(config.clone())?)),
        OutboundType::Trojan => Some(Arc::new(TrojanOutbound::new(config.clone())?)),
        OutboundType::Wireguard => Some(Arc::new(WireguardOutbound::new(config.clone())?)),
        OutboundType::Selector
        | OutboundType::Urltest
        | OutboundType::Fallback
        | OutboundType::Loadbalance
        | OutboundType::Relay => None,
    };
    Ok(proxy)
}

impl OutboundManager {
    pub async fn new(config: Arc<RwLock<Config>>) -> Result<Self> {
        let proxies: ProxyRegistry = Arc::new(RwLock::new(HashMap::new()));
        let proxy_providers = Arc::new(ProxyProviderManager::new());
        let (proxy_list, provider_tags) = {
            let config_read = config.read().await;
            Self::build_outbounds(&config_read, &proxies, &proxy_providers).await?
        };

        Ok(Self {
            config,
            proxies,
            proxy_list: parking_lot::RwLock::new(proxy_list),
            proxy_providers,
            provider_tags: parking_lot::RwLock::new(provider_tags),
        })
    }

    /// Shared handle to the proxy provider manager (used by the background
    /// provider updater for interval refreshes and health checks).
    pub fn proxy_provider_manager(&self) -> Arc<ProxyProviderManager> {
        Arc::clone(&self.proxy_providers)
    }

    /// Build the outbound registry and lifecycle list from a configuration.
    /// Returns the lifecycle list and the set of tags owned by proxy providers.
    ///
    /// Pass order matters: leaf proxies first, then proxy-provider proxies
    /// (so groups can reference provider tags), then groups themselves.
    async fn build_outbounds(
        config: &Config,
        registry: &ProxyRegistry,
        provider_manager: &ProxyProviderManager,
    ) -> Result<(
        Vec<Arc<dyn OutboundProxy>>,
        std::collections::HashSet<String>,
    )> {
        let mut proxy_list: Vec<Arc<dyn OutboundProxy>> = Vec::new();
        let mut proxy_group_configs: Vec<OutboundConfig> = Vec::new();
        let mut provider_tags: std::collections::HashSet<String> = Default::default();

        // Pass 1: leaf proxies (everything except proxy groups).
        for outbound_config in &config.outbounds {
            let proxy: Option<Arc<dyn OutboundProxy>> = match build_outbound_proxy(outbound_config)
            {
                Ok(proxy) => proxy,
                Err(e) => return Err(e),
            };

            if let Some(p) = proxy {
                let tag = p.tag().to_string();
                proxy_list.push(p.clone());
                registry.write().await.insert(tag, p);
            } else {
                // Group types (Selector/Urltest/…) are resolved in a final
                // pass once every leaf and provider proxy is in the registry.
                proxy_group_configs.push(outbound_config.clone());
            }
        }

        // Pass 2: proxy providers. Load each configured provider (parses its
        // subscription) and register every resulting proxy by tag so proxy
        // groups can reference them. Failures abort startup — a broken
        // provider must never silently fall back to direct.
        let provider_configs = runtime_proxy_providers();
        for provider_config in provider_configs {
            provider_manager.add_provider(provider_config).await?;
        }
        for proxy in provider_manager.get_all_proxies().await {
            let tag = proxy.tag().to_string();
            provider_tags.insert(tag.clone());
            proxy_list.push(proxy.clone());
            registry.write().await.insert(tag, proxy);
        }

        // Pass 3: proxy groups with access to the registry. A group's
        // `use: [provider]` option is expanded into explicit member tags
        // before construction (Clash semantics).
        for mut group_config in proxy_group_configs {
            Self::expand_provider_use(&mut group_config, provider_manager).await?;
            let proxy: Arc<dyn OutboundProxy> =
                Arc::new(SelectorOutbound::new(group_config, registry.clone())?);
            let tag = proxy.tag().to_string();
            proxy_list.push(proxy.clone());
            registry.write().await.insert(tag, proxy);
        }

        Ok((proxy_list, provider_tags))
    }

    /// Re-sync provider-origin entries in the shared registry after the
    /// background updater refreshed the providers. Removes tags that
    /// disappeared from the subscriptions and re-registers current nodes.
    pub async fn sync_provider_proxies(&self) -> Result<()> {
        let current: Vec<Arc<dyn OutboundProxy>> = self.proxy_providers.get_all_proxies().await;
        let current_tags: std::collections::HashSet<String> = current
            .iter()
            .map(|proxy| proxy.tag().to_string())
            .collect();

        let mut registry = self.proxies.write().await;
        let mut tags = self.provider_tags.write();
        // Drop entries whose provider node disappeared.
        let stale: Vec<String> = tags
            .iter()
            .filter(|tag| !current_tags.contains(*tag))
            .cloned()
            .collect();
        for tag in stale {
            registry.remove(&tag);
            tags.remove(&tag);
        }
        // Register or refresh current nodes.
        for proxy in current {
            let tag = proxy.tag().to_string();
            tags.insert(tag.clone());
            registry.insert(tag, proxy);
        }
        tracing::info!("Synced {} provider proxies into the registry", tags.len());
        Ok(())
    }

    /// Expand a proxy group's `use: [provider, …]` option (Clash semantics)
    /// into explicit `outbounds` members resolved from the loaded providers.
    /// Explicitly listed `outbounds` are kept and provider members appended.
    async fn expand_provider_use(
        group_config: &mut OutboundConfig,
        provider_manager: &ProxyProviderManager,
    ) -> Result<()> {
        let Some(use_value) = group_config.options.get("use") else {
            return Ok(());
        };

        let use_names: Vec<String> = if let Some(arr) = use_value.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(s) = use_value.as_str() {
            nextjson::from_str::<Vec<String>>(s).unwrap_or_default()
        } else {
            return Err(Error::config(format!(
                "Proxy group '{}' has an invalid 'use' value",
                group_config.tag
            )));
        };

        if use_names.is_empty() {
            return Ok(());
        }

        let mut members: Vec<String> = group_config
            .options
            .get("outbounds")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for use_name in &use_names {
            let provider = provider_manager
                .get_provider(use_name)
                .await
                .ok_or_else(|| {
                    Error::config(format!(
                        "Proxy group '{}' references unknown proxy provider '{}'",
                        group_config.tag, use_name
                    ))
                })?;
            for proxy in provider.get_proxies().await {
                let tag = proxy.tag().to_string();
                if !members.contains(&tag) {
                    members.push(tag);
                }
            }
        }

        if members.is_empty() {
            return Err(Error::config(format!(
                "Proxy group '{}' has no outbounds after expanding 'use'",
                group_config.tag
            )));
        }

        group_config.options.insert(
            "outbounds".to_string(),
            nextjson::Value::Array(members.into_iter().map(nextjson::Value::String).collect()),
        );
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        // Don't pre-connect outbounds on startup - this makes startup much faster
        // Connections will be established on-demand when traffic flows through
        tracing::info!(
            "OutboundManager started with {} proxies (lazy connection mode)",
            self.proxy_list.read().len()
        );
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        // Clone the (cheap) Arc handles, drop the lock, then await — never
        // hold a parking_lot guard across an await point.
        let proxies: Vec<_> = self.proxy_list.read().iter().cloned().collect();
        for proxy in proxies {
            proxy.disconnect().await?;
        }
        Ok(())
    }

    /// Rebuild the proxy pool from the current configuration. Removed
    /// outbounds are dropped; the registry is replaced atomically.
    pub async fn reload(&self) -> Result<()> {
        let rebuilt = {
            let config = self.config.read().await;
            // Reset the registry and providers first so outbounds removed
            // from the config do not linger and stay reachable by tag.
            self.proxies.write().await.clear();
            self.proxy_providers.clear().await;
            Self::build_outbounds(&config, &self.proxies, &self.proxy_providers).await?
        };
        *self.proxy_list.write() = rebuilt.0;
        *self.provider_tags.write() = rebuilt.1;
        tracing::info!(
            "OutboundManager reloaded {} proxies",
            self.proxy_list.read().len()
        );
        Ok(())
    }

    /// Get a proxy by tag
    pub fn get_proxy(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        // Use blocking read since this is called from sync context
        // In production, consider using try_read or making this async
        if let Ok(proxies) = self.proxies.try_read() {
            proxies.get(tag).cloned()
        } else {
            None
        }
    }

    /// Get a proxy by tag (async version)
    pub async fn get_proxy_async(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        self.proxies.read().await.get(tag).cloned()
    }

    /// Get all proxy tags
    pub fn get_all_tags(&self) -> Vec<String> {
        self.proxy_list
            .read()
            .iter()
            .map(|p| p.tag().to_string())
            .collect()
    }

    /// Get config
    pub fn config(&self) -> Arc<RwLock<Config>> {
        self.config.clone()
    }

    /// Get proxy registry (for proxy groups)
    pub fn registry(&self) -> ProxyRegistry {
        self.proxies.clone()
    }

    /// Set the selected proxy in a selector group
    pub async fn set_selector_proxy(&self, group_tag: &str, proxy_tag: &str) -> Result<()> {
        let proxies = self.proxies.read().await;

        if proxies.get(group_tag).is_some() {
            // Use the shared global selections map
            let selections = get_global_selector_selections();
            selections
                .write()
                .insert(group_tag.to_string(), proxy_tag.to_string());

            tracing::info!("Selector '{}' selection set to '{}'", group_tag, proxy_tag);
            Ok(())
        } else {
            Err(Error::config(format!(
                "Proxy group '{}' not found",
                group_tag
            )))
        }
    }

    /// Get the selected proxy in a selector group
    pub fn get_selector_proxy(&self, group_tag: &str) -> Option<String> {
        let selections = get_global_selector_selections();
        selections.read().get(group_tag).cloned()
    }
}

/// Bridge between the background provider updater and this manager's shared
/// proxy registry: after providers are refreshed, replace the provider-owned
/// registry entries so new nodes are immediately reachable by groups.
#[async_trait::async_trait]
impl crate::engine::provider_updater::ProviderRegistrySync for OutboundManager {
    async fn sync_providers(&self) -> Result<()> {
        self.sync_provider_proxies().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::config::{GeneralConfig, InboundConfig, InboundType};
    use crate::engine::proxy_provider::{
        set_runtime_proxy_providers, HealthCheckConfig, ProxyProviderConfig, ProxyProviderType,
    };

    fn test_config() -> Config {
        Config {
            general: GeneralConfig::default(),
            dns: crate::engine::config::DnsConfig::default(),
            inbounds: vec![InboundConfig {
                inbound_type: InboundType::Mixed,
                tag: "mixed-in".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 17890,
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
                    outbound_type: OutboundType::Selector,
                    tag: "PROXY".to_string(),
                    server: None,
                    port: None,
                    options: {
                        let mut options = HashMap::new();
                        options.insert(
                            "use".to_string(),
                            nextjson::Value::Array(vec![nextjson::Value::String(
                                "sub".to_string(),
                            )]),
                        );
                        options.insert(
                            "outbounds".to_string(),
                            nextjson::Value::Array(vec![nextjson::Value::String(
                                "DIRECT".to_string(),
                            )]),
                        );
                        options
                    },
                },
            ],
            rules: Vec::new(),
        }
    }

    fn write_subscription(path: &std::path::Path, tags: &[&str]) {
        let proxies: Vec<nextjson::Value> = tags
            .iter()
            .map(|tag| {
                nextjson::from_str::<nextjson::Value>(&format!(
                    r#"{{"type":"socks5","tag":"{tag}","server":"127.0.0.1","port":1080}}"#
                ))
                .expect("valid proxy json")
            })
            .collect();
        let doc = nextjson::Value::Array(proxies);
        let content = nextjson::to_string(&doc).expect("serialize subscription");
        std::fs::write(path, content).expect("write subscription file");
    }

    #[tokio::test]
    async fn proxy_providers_register_into_registry_and_sync() {
        let dir =
            std::env::temp_dir().join(format!("corduit-outbound-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sub_path = dir.join("sub.json");

        // First generation: p1.
        write_subscription(&sub_path, &["p1"]);
        set_runtime_proxy_providers(vec![ProxyProviderConfig {
            name: "sub".to_string(),
            provider_type: ProxyProviderType::File,
            url: None,
            path: Some(sub_path.to_string_lossy().to_string()),
            interval: 60,
            health_check: HealthCheckConfig {
                enable: false,
                ..HealthCheckConfig::default()
            },
        }]);

        let manager = OutboundManager::new(Arc::new(RwLock::new(test_config())))
            .await
            .expect("outbound manager builds with provider");
        assert!(
            manager.get_proxy_async("p1").await.is_some(),
            "provider proxy p1 must be registered"
        );

        // Group `use: [sub]` must have expanded p1 into its members.
        let group = manager
            .get_proxy_async("PROXY")
            .await
            .expect("selector group exists");
        let outbounds = group.tag().to_string();
        assert_eq!(outbounds, "PROXY");

        // Second generation: subscription now yields p2 (p1 gone).
        write_subscription(&sub_path, &["p2"]);
        manager
            .proxy_provider_manager()
            .reload_provider("sub")
            .await
            .expect("provider reload");
        manager
            .sync_provider_proxies()
            .await
            .expect("registry sync");

        assert!(
            manager.get_proxy_async("p2").await.is_some(),
            "refreshed proxy p2 must be registered after sync"
        );
        assert!(
            manager.get_proxy_async("p1").await.is_none(),
            "stale proxy p1 must be removed after sync"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
