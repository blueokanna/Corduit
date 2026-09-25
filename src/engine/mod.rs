//! # Corduit Core
//!
//! The unified engine behind **Corduit** — a single, non-composite network proxy
//! engine written in Rust. This module owns configuration modelling & validation,
//! the typed rule-routing pipeline, inbound/outbound orchestration, proxy
//! groups, health checks, provider updates and per-connection traffic
//! accounting.
//!
//! ## Highlights
//!
//! * **One validated [`Config`] model** mapped from YAML — no ad-hoc dialects.
//! * **Typed rule pipeline** ([`routing`]) with rule / global / direct modes.
//! * **Dependency-inverted GeoIP** via [`geoip::CountryMatcher`] — swap the
//!   database without touching the engine.
//! * **Inbound listeners** ([`inbound`]): HTTP, SOCKS5 and mixed.
//! * **Outbound protocols & groups** ([`outbound`]): Shadowsocks, VMess, VLESS,
//!   Trojan, HTTP(S), SOCKS5, Direct, Reject — plus selector / url-test /
//!   fallback / load-balance / relay groups. WireGuard (feature `wireguard`),
//!   TUIC v5 (feature `tuic`) and Hysteria2 (feature `hysteria2`) are
//!   feature-gated; the two QUIC-based ones are off by default.
//! * **Hot reload** ([`Corduit::reload`]) with atomic config swaps.
//! * **Observability**: `tracing`-based structured logging and span helpers.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use corduit::engine::{
//!     Config, Corduit, GeneralConfig, InboundConfig, InboundType, OutboundConfig, OutboundType,
//! };
//!
//! fn main() -> corduit::engine::Result<()> {
//!     // `Config::default()` alone fails validation (no inbound), so build a
//!     // real one: one mixed inbound + a DIRECT outbound.
//!     let config = Config {
//!         general: GeneralConfig {
//!             mixed_port: Some(17890),
//!             ..GeneralConfig::default()
//!         },
//!         inbounds: vec![InboundConfig {
//!             inbound_type: InboundType::Mixed,
//!             tag: "mixed-in".to_string(),
//!             listen: "127.0.0.1".to_string(),
//!             port: 17890,
//!             options: Default::default(),
//!         }],
//!         outbounds: vec![OutboundConfig {
//!             outbound_type: OutboundType::Direct,
//!             tag: "DIRECT".to_string(),
//!             server: None,
//!             port: None,
//!             options: Default::default(),
//!         }],
//!         ..Config::default()
//!     };
//!
//!     let engine = Corduit::new(config)?;
//!     engine.start()?;
//!     // ... run the proxy ...
//!     engine.stop()
//! }
//! ```

#[macro_use]
pub mod macros;
pub mod api;
pub mod config;
pub mod connection_pool;
pub mod connection_tracker;
pub mod dns;
pub mod error;
pub mod geoip;
pub mod health_check;
pub mod inbound;
pub mod logging;
pub mod mmdb;
pub mod outbound;
pub mod process;
pub mod provider_updater;
pub mod proxy;
pub mod proxy_provider;
pub mod random;
pub mod routing;
pub mod rule_provider;
pub mod tls;
pub mod traffic_stats;

#[cfg(test)]
mod tests;

pub use config::*;
pub use connection_pool::*;
pub use connection_tracker::global_tracker;
pub use connection_tracker::ConnectionHandle;
pub use connection_tracker::ConnectionTracker;
pub use connection_tracker::TrackedConnection;
pub use error::*;
pub use health_check::*;
pub use proxy::*;
pub use routing::proxy_mode;
pub use routing::{get_runtime_proxy_mode, set_runtime_proxy_mode, set_runtime_rule_providers};
pub use traffic_stats::TrafficStats;
pub use traffic_stats::TrafficStatsManager;
pub use traffic_stats::TrafficSummary;

use std::time::Instant;

/// The main Corduit proxy server
pub struct Corduit {
    config: Config,
    proxy_manager: std::sync::Arc<ProxyManager>,
    traffic_stats: std::sync::Arc<TrafficStatsManager>,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    start_time: std::sync::Arc<std::sync::RwLock<Option<Instant>>>,
    /// The client-facing DNS listener, when `dns.enable` is set.
    ///
    /// Owned by the engine rather than kept in a process-wide static because a
    /// listener's lifetime *is* the engine's: bound on start, unbound on stop,
    /// rebound on reload. A static would have to be told which engine it
    /// belongs to, and there is only ever one.
    dns_listener: parking_lot::Mutex<Option<crate::dns::DnsServer>>,
}

impl Corduit {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        logging::init_logging(config.general.log_level)?;
        crate::dns::engine_resolver::configure(config.dns.resolver_settings());
        crate::common::socket::set_tcp_concurrent(config.general.tcp_concurrent);

        let proxy_manager = ProxyManager::new(config.clone())?;
        let traffic_stats = TrafficStatsManager::new();

        logging::log_success("Corduit instance created", None);

        Ok(Self {
            config,
            proxy_manager: std::sync::Arc::new(proxy_manager),
            traffic_stats: std::sync::Arc::new(traffic_stats),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            start_time: std::sync::Arc::new(std::sync::RwLock::new(None)),
            dns_listener: parking_lot::Mutex::new(None),
        })
    }

    /// Bind the client-facing DNS listener, if the profile asked for one.
    ///
    /// Not fatal. A listener that cannot bind its port is a real problem, but it
    /// is not a reason to refuse to run a proxy: the operator asked for two
    /// things and losing one must not take the other with it. The warning names
    /// the address, so the reason is one line away.
    fn start_dns_listener(&self) {
        let dns = &self.config.dns;
        if !dns.enable {
            return;
        }

        let listen = match dns.listen.trim().parse::<std::net::SocketAddr>() {
            Ok(address) => address,
            Err(error) => {
                tracing::warn!(
                    "dns.listen '{}' is not an address ({error}); no DNS listener started",
                    dns.listen
                );
                return;
            }
        };

        if dns.enhanced_mode == DnsMode::FakeIp {
            tracing::info!(
                "dns.enhanced-mode is fake-ip, but the DNS listener answers with real addresses: \
                 a synthesized address is only useful to something that can map it back, and only \
                 the netstack's responder owns that pool"
            );
        }

        let started = crate::dns::engine_resolver::client_resolver(dns.resolver_settings())
            .and_then(|resolver| {
                crate::dns::DnsServer::start(resolver, listen).map_err(|error| error.to_string())
            });
        match started {
            Ok(server) => *self.dns_listener.lock() = Some(server),
            Err(error) => tracing::warn!("DNS listener could not start on {listen}: {error}"),
        }
    }

    /// Stop the listener, if one is running.
    fn stop_dns_listener(&self) {
        if let Some(server) = self.dns_listener.lock().take() {
            server.stop();
        }
    }

    /// Start the proxy server
    pub fn start(&self) -> Result<()> {
        let _perf = logging::time_operation("Corduit startup");

        // Start inbound listeners
        self.proxy_manager.start_inbounds()?;

        // Start outbound connections pool
        self.proxy_manager.start_outbounds()?;

        // Start background provider refreshes (proxy/rule providers, health checks)
        self.proxy_manager.start_providers()?;

        // Start the client-facing DNS listener, if `dns.enable` asked for one
        self.start_dns_listener();

        // Mark as running and record start time
        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut start_time) = self.start_time.write() {
            *start_time = Some(Instant::now());
        }

        logging::log_success("Corduit proxy server started", None);
        Ok(())
    }

    /// Stop the proxy server
    pub fn stop(&self) -> Result<()> {
        let _perf = logging::time_operation("Corduit shutdown");

        // The listener goes first: it is answering clients that are about to be
        // told the engine is gone, and leaving it up while the proxy tears down
        // would hand out answers the engine can no longer honour.
        self.stop_dns_listener();

        match self.proxy_manager.stop() {
            Ok(()) => {
                self.running
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut start_time) = self.start_time.write() {
                    *start_time = None;
                }
                logging::log_success("Corduit proxy server stopped", None);
                Ok(())
            }
            Err(e) => {
                self.running
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut start_time) = self.start_time.write() {
                    *start_time = None;
                }
                logging::log_error(&e, Some("Failed to stop proxy server"));
                Err(e)
            }
        }
    }

    /// Check if the proxy server is running
    pub fn is_running(&self) -> Result<bool> {
        Ok(self.running.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        if let Ok(start_time) = self.start_time.read() {
            if let Some(start) = *start_time {
                return start.elapsed().as_secs();
            }
        }
        0
    }

    /// Reload configuration
    pub fn reload(&mut self, config: Config) -> Result<()> {
        tracing::info!("Reloading Corduit configuration");
        crate::dns::engine_resolver::configure(config.dns.resolver_settings());
        crate::common::socket::set_tcp_concurrent(config.general.tcp_concurrent);
        self.proxy_manager.reload(config.clone())?;
        self.config = config;

        // Rebinding is the only way a changed `dns.listen`, `dns.enable` or
        // upstream set takes effect: a listener holds its resolver for its whole
        // life, and the resolver holds the forwarders it was built with.
        self.stop_dns_listener();
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            self.start_dns_listener();
        }

        tracing::info!("Corduit configuration reloaded");
        Ok(())
    }

    /// Get a reference to the proxy manager
    pub fn proxy_manager(&self) -> std::sync::Arc<ProxyManager> {
        std::sync::Arc::clone(&self.proxy_manager)
    }

    /// Get a reference to the traffic stats manager
    pub fn traffic_stats(&self) -> std::sync::Arc<TrafficStatsManager> {
        std::sync::Arc::clone(&self.traffic_stats)
    }

    /// Get current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}
