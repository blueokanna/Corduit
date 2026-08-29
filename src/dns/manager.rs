//! DNS Manager - Unified DNS management for Corduit
//!
//! Provides a high-level interface for DNS resolution with support for:
//! - Multiple upstream protocols (UDP/TCP/DoH/DoT)
//! - DNS caching with TTL awareness
//! - Fake-IP mode for transparent proxying
//! - DNS server functionality
//! - Hot-reload configuration

use crate::common::exec;
use crate::dns::config::DnsConfig;
use crate::dns::doh::DohResolver;
use crate::dns::dot::DotResolver;
use crate::dns::error::Result;
use crate::dns::resolver::DnsResolver;
use crate::dns::server::DnsServer;
use crate::dns::RecordType;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// DNS Manager state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsManagerState {
    /// Not started
    Stopped,
    /// Running normally
    Running,
    /// Error state
    Error,
}

/// DNS Manager for Corduit
///
/// Provides unified DNS resolution with support for:
/// - Standard UDP/TCP DNS
/// - DNS over HTTPS (DoH)
/// - DNS over TLS (DoT)
/// - Fake-IP mode for transparent proxying
/// - DNS caching
/// - Local DNS server
pub struct DnsManager {
    /// DNS resolver
    resolver: Arc<RwLock<DnsResolver>>,
    /// DNS server (optional)
    server: Arc<RwLock<Option<Arc<DnsServer>>>>,
    /// DoH resolver (optional)
    doh_resolver: Option<Arc<DohResolver>>,
    /// DoT resolver (optional)
    dot_resolver: Option<Arc<DotResolver>>,
    /// Configuration
    config: Arc<RwLock<DnsConfig>>,
    /// Current state
    state: Arc<RwLock<DnsManagerState>>,
}

impl DnsManager {
    /// Create a new DNS manager with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(DnsConfig::default())
    }

    /// Create a new DNS manager with custom configuration
    pub fn with_config(config: DnsConfig) -> Result<Self> {
        let resolver = DnsResolver::new(config.clone())?;

        // Create DoH resolver if configured
        let doh_resolver = Self::create_doh_resolver(&config);

        // Create DoT resolver if configured
        let dot_resolver = Self::create_dot_resolver(&config);

        info!(
            "DNS manager initialized: doh={}, dot={}, fake_ip={}",
            doh_resolver.is_some(),
            dot_resolver.is_some(),
            config.fake_ip
        );

        Ok(Self {
            resolver: Arc::new(RwLock::new(resolver)),
            server: Arc::new(RwLock::new(None)),
            doh_resolver,
            dot_resolver,
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(DnsManagerState::Stopped)),
        })
    }

    /// Create DoH resolver from config
    fn create_doh_resolver(config: &DnsConfig) -> Option<Arc<DohResolver>> {
        let doh_urls: Vec<String> = config
            .nameservers
            .iter()
            .filter(|s| s.starts_with("https://"))
            .cloned()
            .collect();

        if doh_urls.is_empty() {
            return None;
        }

        match DohResolver::new(&doh_urls) {
            Ok(resolver) => {
                debug!("DoH resolver created with {} servers", doh_urls.len());
                Some(Arc::new(resolver))
            }
            Err(e) => {
                warn!("Failed to create DoH resolver: {}", e);
                None
            }
        }
    }

    /// Create DoT resolver from config
    fn create_dot_resolver(config: &DnsConfig) -> Option<Arc<DotResolver>> {
        let dot_urls: Vec<String> = config
            .nameservers
            .iter()
            .filter(|s| s.starts_with("tls://"))
            .cloned()
            .collect();

        if dot_urls.is_empty() {
            return None;
        }

        match DotResolver::from_urls(&dot_urls) {
            Ok(resolver) => {
                debug!("DoT resolver created with {} servers", dot_urls.len());
                Some(Arc::new(resolver))
            }
            Err(e) => {
                warn!("Failed to create DoT resolver: {}", e);
                None
            }
        }
    }

    /// Resolve a domain name to IP addresses
    ///
    /// Resolution order:
    /// 1. DoH (if available and preferred)
    /// 2. DoT (if available)
    /// 3. Standard resolver (UDP/TCP with caching, Fake-IP, etc.)
    pub fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.resolve_with_type(domain, RecordType::A)
    }

    /// Resolve with specific record type
    pub fn resolve_with_type(&self, domain: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let domain = domain.trim_end_matches('.');

        // Try DoH first if available
        if let Some(doh) = &self.doh_resolver {
            match doh.query(domain, record_type) {
                Ok(ips) if !ips.is_empty() => {
                    debug!("DoH resolved {} to {:?}", domain, ips);
                    return Ok(ips);
                }
                Ok(_) => debug!("DoH returned empty result for {}", domain),
                Err(e) => debug!("DoH resolution failed for {}: {}", domain, e),
            }
        }

        // Try DoT if available
        if let Some(dot) = &self.dot_resolver {
            match dot.query(domain, record_type) {
                Ok(ips) if !ips.is_empty() => {
                    debug!("DoT resolved {} to {:?}", domain, ips);
                    return Ok(ips);
                }
                Ok(_) => debug!("DoT returned empty result for {}", domain),
                Err(e) => debug!("DoT resolution failed for {}: {}", domain, e),
            }
        }

        // Fall back to standard resolver
        let resolver = self.resolver.read();
        resolver.resolve(domain, record_type)
    }

    /// Resolve IPv4 addresses only
    pub fn resolve_a(&self, domain: &str) -> Result<Vec<std::net::Ipv4Addr>> {
        let ips = self.resolve_with_type(domain, RecordType::A)?;
        Ok(ips
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .collect())
    }

    /// Resolve IPv6 addresses only
    pub fn resolve_aaaa(&self, domain: &str) -> Result<Vec<std::net::Ipv6Addr>> {
        let ips = self.resolve_with_type(domain, RecordType::AAAA)?;
        Ok(ips
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                _ => None,
            })
            .collect())
    }

    /// Start DNS server
    pub fn start_server(&self) -> Result<()> {
        let config = self.config.read();

        if !config.enable {
            return Ok(());
        }

        let server = Arc::new(DnsServer::new(config.clone())?);

        // Store server reference
        *self.server.write() = Some(server.clone());

        // Start server in background (runs until `stop_server`).
        exec::spawn(move || {
            if let Err(e) = server.start() {
                warn!("DNS server error: {}", e);
            }
        });

        *self.state.write() = DnsManagerState::Running;
        info!("DNS server started on {}", config.listen);
        Ok(())
    }

    /// Stop DNS server
    pub fn stop_server(&self) -> Result<()> {
        let mut server_lock = self.server.write();
        if let Some(server) = server_lock.take() {
            server.stop();
            info!("DNS server stopped");
        }
        *self.state.write() = DnsManagerState::Stopped;
        Ok(())
    }

    /// Check if DNS server is running
    pub fn is_server_running(&self) -> bool {
        self.server.read().is_some()
    }

    /// Get current state
    pub fn state(&self) -> DnsManagerState {
        *self.state.read()
    }

    /// Check if DoH is enabled
    pub fn has_doh(&self) -> bool {
        self.doh_resolver.is_some()
    }

    /// Check if DoT is enabled
    pub fn has_dot(&self) -> bool {
        self.dot_resolver.is_some()
    }

    /// Lookup domain from Fake-IP
    pub fn lookup_fake_ip(&self, ip: std::net::Ipv4Addr) -> Option<String> {
        let resolver = self.resolver.read();
        resolver.lookup_fake_ip(ip)
    }

    /// Check if IP is a Fake-IP
    pub fn is_fake_ip(&self, ip: std::net::Ipv4Addr) -> bool {
        let resolver = self.resolver.read();
        resolver.is_fake_ip(ip)
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStatistics {
        let resolver = self.resolver.read();
        let cache = resolver.cache();
        let stats = cache.stats();

        CacheStatistics {
            size: cache.len(),
            hits: stats.hits.load(std::sync::atomic::Ordering::Relaxed),
            misses: stats.misses.load(std::sync::atomic::Ordering::Relaxed),
            hit_rate: stats.hit_rate(),
        }
    }

    /// Clear DNS cache
    pub fn clear_cache(&self) {
        let resolver = self.resolver.read();
        resolver.clear_cache();
        info!("DNS cache cleared");
    }

    /// Reset DNS manager (clear cache, stop server, reinitialize)
    pub fn reset(&self) -> Result<()> {
        info!("Resetting DNS manager...");

        // Stop server if running
        self.stop_server()?;

        // Clear cache
        self.clear_cache();

        // Cleanup resolver
        {
            let resolver = self.resolver.read();
            resolver.cleanup();
        }

        info!("DNS manager reset complete");
        Ok(())
    }

    /// Reload configuration
    pub fn reload_config(&self, new_config: DnsConfig) -> Result<()> {
        info!("Reloading DNS configuration...");

        // Stop server if running
        let was_running = self.is_server_running();
        if was_running {
            self.stop_server()?;
        }

        // Create new resolver
        let new_resolver = DnsResolver::new(new_config.clone())?;

        // Update resolver
        {
            let mut resolver = self.resolver.write();
            *resolver = new_resolver;
        }

        // Update config
        {
            let mut config = self.config.write();
            *config = new_config;
        }

        // Restart server if it was running
        if was_running {
            self.start_server()?;
        }

        info!("DNS configuration reloaded");
        Ok(())
    }

    /// Get current configuration
    pub fn config(&self) -> DnsConfig {
        self.config.read().clone()
    }

    /// Get resolver reference (for advanced usage)
    pub fn resolver(&self) -> &Arc<RwLock<DnsResolver>> {
        &self.resolver
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStatistics {
    /// Current cache size
    pub size: usize,
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Hit rate (0.0 - 1.0)
    pub hit_rate: f64,
}

impl Default for DnsManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default DNS manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_manager_creation() {
        let manager = DnsManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_dns_manager_with_config() {
        let config = DnsConfig {
            nameservers: vec![
                "8.8.8.8".to_string(),
                "https://dns.google/dns-query".to_string(),
            ],
            ..Default::default()
        };

        let manager = DnsManager::with_config(config);
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert!(manager.has_doh());
    }

    #[test]
    fn test_dns_manager_state() {
        let manager = DnsManager::new().unwrap();
        assert_eq!(manager.state(), DnsManagerState::Stopped);
    }

    #[test]
    #[ignore] // Requires network
    fn test_dns_manager_resolve() {
        let manager = DnsManager::new().unwrap();
        let result = manager.resolve("google.com");
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
}
