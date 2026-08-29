use crate::engine::config::Config;
use crate::engine::error::Result;
use crate::engine::inbound::InboundManager;
use crate::engine::outbound::OutboundManager;
use crate::engine::provider_updater::{
    ProviderRegistrySync, ProviderUpdater, ProviderUpdaterConfig,
};
use crate::engine::routing::Router;
use parking_lot::RwLock;
use std::sync::Arc;

/// Proxy manager that coordinates inbound and outbound connections
pub struct ProxyManager {
    config: Arc<RwLock<Config>>,
    inbound_manager: InboundManager,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    /// Background worker that refreshes proxy/rule providers and runs health
    /// checks on their configured intervals.
    provider_updater: ProviderUpdater,
}

impl ProxyManager {
    /// Create a new proxy manager
    pub fn new(config: Config) -> Result<Self> {
        let config_arc = Arc::new(RwLock::new(config));

        // Router first: it loads rule providers and validates that every
        // RULE-SET rule references a configured provider.
        let router = Arc::new(Router::new(config_arc.clone())?);

        // Outbound manager next: it loads proxy providers into the shared
        // registry so proxy groups can reference provider proxies.
        let outbound_manager = Arc::new(OutboundManager::new(config_arc.clone())?);

        // Provider updater shares the live managers so interval refreshes
        // affect the same proxies/rules traffic is using; the registry sync
        // hook makes refreshed provider nodes reachable without a reload.
        let provider_updater = ProviderUpdater::new(ProviderUpdaterConfig::default())
            .with_proxy_provider_manager(outbound_manager.proxy_provider_manager())
            .with_rule_provider_manager(router.rule_provider_manager_arc())
            .with_proxy_registry_sync(
                Arc::clone(&outbound_manager) as Arc<dyn ProviderRegistrySync>
            );

        // Create inbound manager with reference to outbound manager
        let inbound_manager = InboundManager::new(
            config_arc.clone(),
            router.clone(),
            Arc::clone(&outbound_manager),
        )?;

        Ok(Self {
            config: config_arc,
            inbound_manager,
            outbound_manager,
            router,
            provider_updater,
        })
    }

    /// Start all inbound listeners
    pub fn start_inbounds(&self) -> Result<()> {
        self.inbound_manager.start()
    }

    /// Start outbound connection pools
    pub fn start_outbounds(&self) -> Result<()> {
        self.outbound_manager.start()
    }

    /// Start the background provider updater (interval refresh + health check).
    pub fn start_providers(&self) -> Result<()> {
        self.provider_updater.start()
    }

    /// Stop the background provider updater.
    pub fn stop_providers(&self) -> Result<()> {
        self.provider_updater.stop()
    }

    /// Stop all proxy services
    pub fn stop(&self) -> Result<()> {
        self.stop_providers()?;
        self.inbound_manager.stop()?;
        self.outbound_manager.stop()?;
        Ok(())
    }

    /// Reload configuration.
    ///
    /// The config write lock is released before the router/inbound/outbound
    /// reloads run, because each of those takes a read lock on the *same*
    /// `RwLock` (parking_lot's `RwLock` is not re-entrant — holding the
    /// write lock here would deadlock).
    pub fn reload(&self, new_config: Config) -> Result<()> {
        {
            let mut config = self.config.write();
            *config = new_config;
        }

        self.router.reload()?;
        self.inbound_manager.reload()?;
        self.outbound_manager.reload()?;

        Ok(())
    }

    /// Get current configuration
    pub fn get_config(&self) -> Config {
        self.config.read().clone()
    }

    /// Get router reference
    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
    }

    /// Get inbound manager reference
    pub fn inbound_manager(&self) -> &InboundManager {
        &self.inbound_manager
    }

    /// Get outbound manager reference
    pub fn outbound_manager(&self) -> &OutboundManager {
        &self.outbound_manager
    }
}
