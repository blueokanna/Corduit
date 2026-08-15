use crate::engine::config::Config;
use crate::engine::error::Result;
use crate::engine::inbound::InboundManager;
use crate::engine::outbound::OutboundManager;
use crate::engine::provider_updater::{
    ProviderRegistrySync, ProviderUpdater, ProviderUpdaterConfig,
};
use crate::engine::routing::Router;
use std::sync::Arc;
use tokio::sync::RwLock;

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
    pub async fn new(config: Config) -> Result<Self> {
        let config_arc = Arc::new(RwLock::new(config));

        // Router first: it loads rule providers and validates that every
        // RULE-SET rule references a configured provider.
        let router = Arc::new(Router::new(config_arc.clone()).await?);

        // Outbound manager next: it loads proxy providers into the shared
        // registry so proxy groups can reference provider proxies.
        let outbound_manager = Arc::new(OutboundManager::new(config_arc.clone()).await?);

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
        )
        .await?;

        Ok(Self {
            config: config_arc,
            inbound_manager,
            outbound_manager,
            router,
            provider_updater,
        })
    }

    /// Start all inbound listeners
    pub async fn start_inbounds(&self) -> Result<()> {
        self.inbound_manager.start().await
    }

    /// Start outbound connection pools
    pub async fn start_outbounds(&self) -> Result<()> {
        self.outbound_manager.start().await
    }

    /// Start the background provider updater (interval refresh + health check).
    pub async fn start_providers(&self) -> Result<()> {
        self.provider_updater.start().await
    }

    /// Stop the background provider updater.
    pub async fn stop_providers(&self) -> Result<()> {
        self.provider_updater.stop().await
    }

    /// Stop all proxy services
    pub async fn stop(&self) -> Result<()> {
        self.stop_providers().await?;
        self.inbound_manager.stop().await?;
        self.outbound_manager.stop().await?;
        Ok(())
    }

    /// Reload configuration.
    ///
    /// The config lock is released before the router/inbound/outbound reloads
    /// run, because each of those takes a read lock on the *same* `RwLock`
    /// (a tokio `RwLock` is not re-entrant — holding the write lock here would
    /// deadlock).
    pub async fn reload(&self, new_config: Config) -> Result<()> {
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }

        self.router.reload().await?;
        self.inbound_manager.reload().await?;
        self.outbound_manager.reload().await?;

        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> Config {
        self.config.read().await.clone()
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
