//! # Corduit Core
//!
//! The unified engine behind **Corduit** — a single, non-composite network proxy
//! engine written in Rust. This crate owns configuration modelling & validation,
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
//!   Trojan, WireGuard, HTTP(S), SOCKS5, Direct, Reject — plus selector /
//!   url-test / fallback / load-balance / relay groups.
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
//! #[tokio::main]
//! async fn main() -> corduit::engine::Result<()> {
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
//!     let engine = Corduit::new(config).await?;
//!     engine.start().await?;
//!     // ... run the proxy ...
//!     engine.stop().await
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
pub mod jaeger_tracing;
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
}

impl Corduit {
    pub async fn new(config: Config) -> Result<Self> {
        config.validate()?;
        logging::init_logging(config.general.log_level)?;

        // Keep the legacy rustls provider hook for API compatibility; the
        // courierust TLS layer does not need it.
        tls::install_crypto_provider();

        let proxy_manager = ProxyManager::new(config.clone()).await?;
        let traffic_stats = TrafficStatsManager::new();

        logging::log_success("Corduit instance created", None);

        Ok(Self {
            config,
            proxy_manager: std::sync::Arc::new(proxy_manager),
            traffic_stats: std::sync::Arc::new(traffic_stats),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            start_time: std::sync::Arc::new(std::sync::RwLock::new(None)),
        })
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let _perf = logging::time_operation("Corduit startup");

        // Start inbound listeners
        self.proxy_manager.start_inbounds().await?;

        // Start outbound connections pool
        self.proxy_manager.start_outbounds().await?;

        // Start background provider refreshes (proxy/rule providers, health checks)
        self.proxy_manager.start_providers().await?;

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
    pub async fn stop(&self) -> Result<()> {
        let _perf = logging::time_operation("Corduit shutdown");

        match self.proxy_manager.stop().await {
            Ok(()) => {
                // Mark as not running and clear start time
                self.running
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                if let Ok(mut start_time) = self.start_time.write() {
                    *start_time = None;
                }
                logging::log_success("Corduit proxy server stopped", None);
                Ok(())
            }
            Err(e) => {
                // Mark as not running even on error
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
    pub async fn is_running(&self) -> Result<bool> {
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
    pub async fn reload(&mut self, config: Config) -> Result<()> {
        tracing::info!("Reloading Corduit configuration");
        self.proxy_manager.reload(config.clone()).await?;
        self.config = config;
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
