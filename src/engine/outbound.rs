//! Outbound proxies and the shared outbound manager.
//!
//! The [`OutboundProxy`] trait is the synchronous contract every outbound
//! protocol implements: `relay_tcp` accepts a client
//! [`BoxStream`](crate::common::stream::BoxStream) and a target, establishes
//! the upstream connection, and returns once the relay finishes.
//!
//! Concurrency model: every method is blocking; long-lived relays run on
//! dedicated threads spawned by [`relay`](crate::common::stream::relay) and
//! are bounded by the engine's session gate.

use crate::common::stream::BoxStream;
use crate::engine::config::{Config, OutboundConfig, OutboundType};
use crate::engine::error::{Error, Result};
use crate::engine::proxy_provider::{runtime_proxy_providers, ProxyProviderManager};
use parking_lot::RwLock as ParkingRwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;

mod direct;
mod http;
mod hysteria2;
mod reject;
mod selector;
mod shadowsocks;
mod socks5;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod wireguard;

pub use direct::relay_bidirectional_with_connection;
pub use direct::DirectOutbound;
pub use http::HttpOutbound;
pub use hysteria2::Hysteria2Outbound;
pub use reject::RejectOutbound;
pub use selector::SelectorOutbound;
pub use shadowsocks::ShadowsocksOutbound;
pub use socks5::Socks5Outbound;
pub use trojan::TrojanOutbound;
pub use tuic::TuicOutbound;
pub use vless::VlessOutbound;
pub use vmess::VmessOutbound;
pub use wireguard::WireguardOutbound;

static GLOBAL_SELECTOR_SELECTIONS: OnceLock<ParkingRwLock<HashMap<String, String>>> =
    OnceLock::new();

pub fn get_global_selector_selections() -> &'static ParkingRwLock<HashMap<String, String>> {
    GLOBAL_SELECTOR_SELECTIONS.get_or_init(|| ParkingRwLock::new(HashMap::new()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub type ProxyRegistry = Arc<ParkingRwLock<HashMap<String, Arc<dyn OutboundProxy>>>>;

/// A built outbound set: the lifecycle list plus the set of tags owned by
/// proxy providers (so a background refresh can replace exactly those
/// registry entries).
pub(crate) type BuiltOutbounds = (
    Vec<Arc<dyn OutboundProxy>>,
    std::collections::HashSet<String>,
);

pub struct OutboundManager {
    config: Arc<ParkingRwLock<Config>>,
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

/// The synchronous outbound contract. Every method blocks the calling
/// worker; the caller is expected to run on a pool worker or a relay thread.
pub trait OutboundProxy: Send + Sync {
    /// Establish (or warm) the upstream connection.
    fn connect(&self) -> Result<()>;

    /// Tear down the upstream connection.
    fn disconnect(&self) -> Result<()>;

    /// The outbound's configured tag.
    fn tag(&self) -> &str;

    /// The upstream server address, if any.
    fn server_addr(&self) -> Option<(String, u16)> {
        None
    }

    /// Whether this outbound can relay UDP.
    fn supports_udp(&self) -> bool {
        false
    }

    /// Relay `inbound` to `target` over this outbound. Blocks until the
    /// relay finishes (EOF both ways, error or cancellation).
    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()>;

    /// Relay with connection tracking (for the traffic dashboard).
    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::engine::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        let _ = connection;
        self.relay_tcp(inbound, target)
    }

    /// Relay a single UDP packet and return the reply.
    fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let _ = (target, data);
        Err(Error::protocol(format!(
            "UDP relay not supported by outbound '{}'",
            self.tag()
        )))
    }

    /// Measure HTTP latency through this outbound.
    fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration>;
}

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
        OutboundType::Tuic => Some(Arc::new(TuicOutbound::new(config.clone())?)),
        OutboundType::Hysteria2 => Some(Arc::new(Hysteria2Outbound::new(config.clone())?)),
        OutboundType::Selector
        | OutboundType::Urltest
        | OutboundType::Fallback
        | OutboundType::Loadbalance
        | OutboundType::Relay => None,
    };
    Ok(proxy)
}

impl OutboundManager {
    pub fn new(config: Arc<ParkingRwLock<Config>>) -> Result<Self> {
        let proxies: ProxyRegistry = Arc::new(ParkingRwLock::new(HashMap::new()));
        let proxy_providers = Arc::new(ProxyProviderManager::new());
        let (proxy_list, provider_tags) = {
            let config_read = config.read();
            Self::build_outbounds(&config_read, &proxies, &proxy_providers)?
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
    fn build_outbounds(
        config: &Config,
        registry: &ProxyRegistry,
        provider_manager: &ProxyProviderManager,
    ) -> Result<BuiltOutbounds> {
        let mut proxy_list: Vec<Arc<dyn OutboundProxy>> = Vec::new();
        let mut proxy_group_configs: Vec<OutboundConfig> = Vec::new();
        let mut provider_tags: std::collections::HashSet<String> = Default::default();

        // Pass 1: leaf proxies (everything except proxy groups).
        for outbound_config in &config.outbounds {
            let proxy: Option<Arc<dyn OutboundProxy>> = build_outbound_proxy(outbound_config)?;

            if let Some(p) = proxy {
                let tag = p.tag().to_string();
                proxy_list.push(p.clone());
                registry.write().insert(tag, p);
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
            provider_manager.add_provider(provider_config)?;
        }
        for proxy in provider_manager.get_all_proxies() {
            let tag = proxy.tag().to_string();
            provider_tags.insert(tag.clone());
            proxy_list.push(proxy.clone());
            registry.write().insert(tag, proxy);
        }

        // Pass 3: proxy groups with access to the registry. A group's
        // `use: [provider]` option is expanded into explicit member tags
        // before construction (Clash semantics).
        for mut group_config in proxy_group_configs {
            Self::expand_provider_use(&mut group_config, provider_manager)?;
            let proxy: Arc<dyn OutboundProxy> =
                Arc::new(SelectorOutbound::new(group_config, registry.clone())?);
            let tag = proxy.tag().to_string();
            proxy_list.push(proxy.clone());
            registry.write().insert(tag, proxy);
        }

        Ok((proxy_list, provider_tags))
    }

    /// Re-sync provider-origin entries in the shared registry after the
    /// background updater refreshed the providers. Removes tags that
    /// disappeared from the subscriptions and re-registers current nodes.
    pub fn sync_provider_proxies(&self) -> Result<()> {
        let current: Vec<Arc<dyn OutboundProxy>> = self.proxy_providers.get_all_proxies();
        let current_tags: std::collections::HashSet<String> = current
            .iter()
            .map(|proxy| proxy.tag().to_string())
            .collect();

        let mut registry = self.proxies.write();
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
    fn expand_provider_use(
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
            let provider = provider_manager.get_provider(use_name).ok_or_else(|| {
                Error::config(format!(
                    "Proxy group '{}' references unknown proxy provider '{}'",
                    group_config.tag, use_name
                ))
            })?;
            for proxy in provider.get_proxies() {
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

    pub fn start(&self) -> Result<()> {
        // Don't pre-connect outbounds on startup - this makes startup much faster
        // Connections will be established on-demand when traffic flows through
        tracing::info!(
            "OutboundManager started with {} proxies (lazy connection mode)",
            self.proxy_list.read().len()
        );
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        let proxies: Vec<_> = self.proxy_list.read().iter().cloned().collect();
        for proxy in proxies {
            proxy.disconnect()?;
        }
        Ok(())
    }

    /// Rebuild the proxy pool from the current configuration. Removed
    /// outbounds are dropped; the registry is replaced atomically.
    pub fn reload(&self) -> Result<()> {
        let rebuilt = {
            let config = self.config.read();
            // Reset the registry and providers first so outbounds removed
            // from the config do not linger and stay reachable by tag.
            self.proxies.write().clear();
            self.proxy_providers.clear();
            Self::build_outbounds(&config, &self.proxies, &self.proxy_providers)?
        };
        *self.proxy_list.write() = rebuilt.0;
        *self.provider_tags.write() = rebuilt.1;
        tracing::info!(
            "OutboundManager reloaded {} proxies",
            self.proxy_list.read().len()
        );
        Ok(())
    }

    /// Get a proxy by tag.
    pub fn get_proxy(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        self.proxies.read().get(tag).cloned()
    }

    /// Get all proxy tags.
    pub fn get_all_tags(&self) -> Vec<String> {
        self.proxy_list
            .read()
            .iter()
            .map(|p| p.tag().to_string())
            .collect()
    }

    /// Get config.
    pub fn config(&self) -> Arc<ParkingRwLock<Config>> {
        self.config.clone()
    }

    /// Get proxy registry (for proxy groups).
    pub fn registry(&self) -> ProxyRegistry {
        self.proxies.clone()
    }

    /// Set the selected proxy in a selector group.
    pub fn set_selector_proxy(&self, group_tag: &str, proxy_tag: &str) -> Result<()> {
        let proxies = self.proxies.read();

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

    /// Get the selected proxy in a selector group.
    pub fn get_selector_proxy(&self, group_tag: &str) -> Option<String> {
        let selections = get_global_selector_selections();
        selections.read().get(group_tag).cloned()
    }
}

/// Bridge between the background provider updater and this manager's shared
/// proxy registry: after providers are refreshed, replace the provider-owned
/// registry entries so new nodes are immediately reachable by groups.
impl crate::engine::provider_updater::ProviderRegistrySync for OutboundManager {
    fn sync_providers(&self) -> Result<()> {
        self.sync_provider_proxies()
    }
}
