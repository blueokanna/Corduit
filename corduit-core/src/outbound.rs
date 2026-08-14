use crate::config::{Config, OutboundConfig, OutboundType};
use crate::error::{Error, Result};
use parking_lot::RwLock as ParkingRwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;

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

impl From<TargetAddr> for corduit_protocol::Address {
    fn from(target: TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain, port) => corduit_protocol::Address::Domain(domain, port),
            TargetAddr::Ip(addr) => corduit_protocol::Address::from_socket_addr(addr),
        }
    }
}

impl From<&TargetAddr> for corduit_protocol::Address {
    fn from(target: &TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain, port) => {
                corduit_protocol::Address::Domain(domain.clone(), *port)
            }
            TargetAddr::Ip(addr) => corduit_protocol::Address::from_socket_addr(*addr),
        }
    }
}

impl From<corduit_protocol::Address> for TargetAddr {
    fn from(addr: corduit_protocol::Address) -> Self {
        match addr {
            corduit_protocol::Address::Domain(domain, port) => TargetAddr::Domain(domain, port),
            corduit_protocol::Address::Ipv4(ip, port) => TargetAddr::Ip(
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)),
            ),
            corduit_protocol::Address::Ipv6(ip, port) => TargetAddr::Ip(
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)),
            ),
        }
    }
}

pub type ProxyRegistry = Arc<RwLock<HashMap<String, Arc<dyn OutboundProxy>>>>;

pub struct OutboundManager {
    config: Arc<RwLock<Config>>,
    proxies: ProxyRegistry,
    /// Lifecycle list (start/stop/tags); replaced atomically on reload.
    proxy_list: parking_lot::RwLock<Vec<Arc<dyn OutboundProxy>>>,
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
        connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
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

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

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
        OutboundType::Quic => {
            return Err(Error::config(format!(
                "QUIC outbound '{}' is not implemented; refusing unsafe direct fallback",
                config.tag
            )));
        }
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
        let proxy_list = {
            let config_read = config.read().await;
            Self::build_outbounds(&config_read, &proxies).await?
        };

        Ok(Self {
            config,
            proxies,
            proxy_list: parking_lot::RwLock::new(proxy_list),
        })
    }

    /// Build the outbound registry and lifecycle list from a configuration.
    ///
    /// The group pass runs after the leaf proxies so selector/urltest/…
    /// groups can reference them through the shared registry.
    async fn build_outbounds(
        config: &Config,
        registry: &ProxyRegistry,
    ) -> Result<Vec<Arc<dyn OutboundProxy>>> {
        let mut proxy_list: Vec<Arc<dyn OutboundProxy>> = Vec::new();
        let mut proxy_group_configs: Vec<OutboundConfig> = Vec::new();

        for outbound_config in &config.outbounds {
            let proxy: Option<Arc<dyn OutboundProxy>> =
                match build_outbound_proxy(outbound_config) {
                    Ok(proxy) => proxy,
                    Err(e) => return Err(e),
                };

            if let Some(p) = proxy {
                let tag = p.tag().to_string();
                proxy_list.push(p.clone());
                registry.write().await.insert(tag, p);
            } else {
                // Group types (Selector/Urltest/…) are resolved in a second
                // pass once every leaf proxy is in the registry.
                proxy_group_configs.push(outbound_config.clone());
            }
        }

        // Second pass: create proxy groups with access to the registry.
        for group_config in proxy_group_configs {
            let proxy: Arc<dyn OutboundProxy> = Arc::new(SelectorOutbound::new(
                group_config.clone(),
                registry.clone(),
            )?);
            let tag = proxy.tag().to_string();
            proxy_list.push(proxy.clone());
            registry.write().await.insert(tag, proxy);
        }

        Ok(proxy_list)
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
        let new_list = {
            let config = self.config.read().await;
            // Reset the registry first so outbounds removed from the config
            // do not linger and stay reachable by tag.
            self.proxies.write().await.clear();
            Self::build_outbounds(&config, &self.proxies).await?
        };
        *self.proxy_list.write() = new_list;
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
