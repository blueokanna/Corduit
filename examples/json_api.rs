//! # JSON-string API (`corduit::api`)
//!
//! The same engine driven through the JSON-string facade that FFI and the
//! JSON-RPC layer use internally: `start_proxy_from_yaml` accepts a full
//! config document (including the `rule_providers` / `proxy_providers`
//! top-level keys), then typed async helpers read runtime state back.
//!
//! ```bash
//! cargo run --example json_api
//! ```

use corduit::api::{
    get_proxies, get_proxy_mode, get_rules, get_traffic_stats_dto, is_proxy_running,
    set_proxy_mode, start_proxy_from_yaml, stop_proxy,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = r#"{
      "general": {
        "mode": "rule",
        "mixed_port": 17892,
        "bind_address": "127.0.0.1",
        "log_level": "info"
      },
      "inbounds": [
        { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 17892 }
      ],
      "outbounds": [
        { "type": "direct", "tag": "DIRECT" },
        {
          "type": "shadowsocks",
          "tag": "ss-node",
          "server": "127.0.0.1",
          "port": 8388,
          "password": "demo-pass",
          "cipher": "aes-256-gcm"
        },
        { "type": "selector", "tag": "PROXY", "outbounds": ["DIRECT", "ss-node"] }
      ],
      "rules": [
        { "type": "domain-suffix", "payload": "google.com", "outbound": "ss-node" },
        { "type": "geoip", "payload": "cn", "outbound": "DIRECT" },
        { "type": "match", "payload": "", "outbound": "PROXY" }
      ],
      "rule_providers": [],
      "proxy_providers": []
    }"#;

    start_proxy_from_yaml(config.to_string()).await?;
    println!("running = {}", is_proxy_running().await?);

    let proxies = get_proxies().await?;
    println!("{} outbound(s):", proxies.len());
    for proxy in proxies {
        println!(
            "  - {:<10} type={:<12} server={:?}:{:?}",
            proxy.tag, proxy.protocol_type, proxy.server, proxy.port
        );
    }

    let rules = get_rules().await?;
    println!("{} rule(s):", rules.len());
    for rule in rules {
        println!(
            "  - {:<16} payload={:<14} -> {}",
            rule.rule_type, rule.payload, rule.outbound
        );
    }

    // Switch the runtime proxy mode: 0=config, 1=global, 2=direct, 3=rule.
    set_proxy_mode(3).await?;
    println!("runtime proxy mode after set = {}", get_proxy_mode().await?);
    set_proxy_mode(0).await?; // back to following config.general.mode

    let stats = get_traffic_stats_dto().await?;
    println!(
        "traffic: up={} down={} connections={} uptime={}s",
        stats.total_upload, stats.total_download, stats.connection_count, stats.uptime_secs
    );

    stop_proxy().await?;
    println!("stopped = {}", !is_proxy_running().await?);
    Ok(())
}
