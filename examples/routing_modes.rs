//! # Routing modes: direct / rule / global
//!
//! Drives the routing engine ([`corduit::engine::routing::Router`]) directly,
//! without binding any sockets, to show how the three modes decide the
//! outbound for a connection:
//!
//! * **rule** (mode `3`): first matching rule wins (Clash semantics);
//! * **direct** (mode `2`): everything goes to the direct outbound;
//! * **global** (mode `1`): everything goes to the proxy group (or the first
//!   non-direct outbound when no group exists);
//! * **config** (mode `0`): fall back to `general.mode`.
//!
//! ```bash
//! cargo run --example routing_modes
//! ```

use corduit::engine::routing::Router;
use corduit::engine::{
    get_runtime_proxy_mode, proxy_mode, set_runtime_proxy_mode, Config, GeneralConfig,
    InboundConfig, InboundType, Mode, OutboundConfig, OutboundType, RuleConfig, RuleType,
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// DIRECT + a plain SOCKS5 node + a two-rule table. Explicit IPs are passed to
/// `match_outbound` so the example never performs DNS lookups.
async fn router() -> Router {
    let config = Config {
        general: GeneralConfig {
            mode: Mode::Rule,
            ..GeneralConfig::default()
        },
        inbounds: vec![InboundConfig {
            inbound_type: InboundType::Mixed,
            tag: "mixed-in".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 17894,
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
                outbound_type: OutboundType::Socks5,
                tag: "socks-node".to_string(),
                server: Some("127.0.0.1".to_string()),
                port: Some(1080),
                options: Default::default(),
            },
        ],
        rules: vec![
            RuleConfig {
                rule_type: RuleType::DomainSuffix,
                payload: "google.com".to_string(),
                outbound: "socks-node".to_string(),
                process_name: None,
            },
            RuleConfig {
                rule_type: RuleType::Match,
                payload: String::new(),
                outbound: "DIRECT".to_string(),
                process_name: None,
            },
        ],
        ..Config::default()
    };
    Router::new(Arc::new(RwLock::new(config)))
        .await
        .expect("router builds")
}

async fn decide(router: &Router, domain: &str, ip: &str) -> String {
    router
        .match_outbound(Some(domain), ip.parse::<IpAddr>().ok(), Some(443), None)
        .await
}

#[tokio::main]
async fn main() {
    let router = router().await;

    // mode 3 = rule
    set_runtime_proxy_mode(proxy_mode::RULE);
    println!("mode = {} (rule)", get_runtime_proxy_mode());
    println!(
        "  google.com  -> {}",
        decide(&router, "google.com", "142.250.0.0").await
    );
    println!(
        "  youtube.com -> {}",
        decide(&router, "youtube.com", "93.184.216.34").await
    );
    println!(
        "  x.com -> {}",
        decide(&router, "x.com", "93.184.216.34").await
    );
    println!(
        "  chatgpt.com -> {}",
        decide(&router, "chatgpt.com", "93.184.216.34").await
    );

    // mode 2 = direct
    set_runtime_proxy_mode(proxy_mode::DIRECT);
    println!("mode = {} (direct)", get_runtime_proxy_mode());
    println!(
        "  google.com  -> {}",
        decide(&router, "google.com", "142.250.0.0").await
    );

    // mode 1 = global: no proxy group in this config, so the first
    // non-direct outbound (socks-node) is used.
    set_runtime_proxy_mode(proxy_mode::GLOBAL);
    println!("mode = {} (global)", get_runtime_proxy_mode());
    println!(
        "  google.com  -> {}",
        decide(&router, "google.com", "142.250.0.0").await
    );

    // mode 0 = follow config.general.mode (rule here)
    set_runtime_proxy_mode(proxy_mode::CONFIG);
    println!("mode = {} (config -> rule)", get_runtime_proxy_mode());
    println!(
        "  x.com -> {}",
        decide(&router, "x.com", "151.101.130.146").await
    );
}
