//! # Full typed configuration + hot reload
//!
//! Builds a complete [`Config`] in Rust (no JSON involved): two inbounds, a
//! direct outbound, a Shadowsocks node and a selector proxy group, plus a
//! three-rule table. Starts the engine, prints its runtime status, then
//! performs a hot reload with a modified config and stops.
//!
//! ```bash
//! cargo run --example typed_config
//! ```
//!
//! Everything binds to `127.0.0.1` on high ports; the Shadowsocks node is
//! **not** contacted — outbound connections are established lazily, so the
//! example works offline.

use corduit::engine::{
    Config, Corduit, GeneralConfig, InboundConfig, InboundType, Mode, OutboundConfig, OutboundType,
    RuleConfig, RuleType,
};
use std::collections::HashMap;

/// One `mixed` inbound + one `socks5` inbound, listening on `127.0.0.1`.
fn inbounds(port: u16) -> Vec<InboundConfig> {
    vec![
        InboundConfig {
            inbound_type: InboundType::Mixed,
            tag: "mixed-in".to_string(),
            listen: "127.0.0.1".to_string(),
            port,
            options: Default::default(),
        },
        InboundConfig {
            inbound_type: InboundType::Socks5,
            tag: "socks-in".to_string(),
            listen: "127.0.0.1".to_string(),
            port: port + 1,
            options: Default::default(),
        },
    ]
}

/// DIRECT + an (unused) Shadowsocks node + a selector group over both.
fn outbounds() -> Vec<OutboundConfig> {
    let mut ss_options = HashMap::new();
    ss_options.insert(
        "password".to_string(),
        nextjson::Value::String("demo-pass".to_string()),
    );
    ss_options.insert(
        "cipher".to_string(),
        nextjson::Value::String("aes-256-gcm".to_string()),
    );

    let mut group_options = HashMap::new();
    group_options.insert(
        "outbounds".to_string(),
        nextjson::Value::Array(vec![
            nextjson::Value::String("DIRECT".to_string()),
            nextjson::Value::String("ss-node".to_string()),
        ]),
    );

    vec![
        OutboundConfig {
            outbound_type: OutboundType::Direct,
            tag: "DIRECT".to_string(),
            server: None,
            port: None,
            options: Default::default(),
        },
        OutboundConfig {
            outbound_type: OutboundType::Shadowsocks,
            tag: "ss-node".to_string(),
            server: Some("127.0.0.1".to_string()),
            port: Some(8388),
            options: ss_options,
        },
        OutboundConfig {
            outbound_type: OutboundType::Selector,
            tag: "PROXY".to_string(),
            server: None,
            port: None,
            options: group_options,
        },
    ]
}

/// Rule table (first match wins, like Clash): proxy Google, direct .cn via
/// GeoIP, everything else through the selector group.
fn rules() -> Vec<RuleConfig> {
    vec![
        RuleConfig {
            rule_type: RuleType::DomainSuffix,
            payload: "google.com".to_string(),
            outbound: "ss-node".to_string(),
            process_name: None,
        },
        RuleConfig {
            rule_type: RuleType::Geoip,
            payload: "cn".to_string(),
            outbound: "DIRECT".to_string(),
            process_name: None,
        },
        RuleConfig {
            rule_type: RuleType::Match,
            payload: String::new(),
            outbound: "PROXY".to_string(),
            process_name: None,
        },
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("CORDUIT_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(17891);

    let config = Config {
        general: GeneralConfig {
            mixed_port: Some(port),
            mode: Mode::Rule,
            ..GeneralConfig::default()
        },
        inbounds: inbounds(port),
        outbounds: outbounds(),
        rules: rules(),
        ..Config::default()
    };

    let mut engine = Corduit::new(config)?;
    engine.start()?;
    println!("engine started, uptime = {}s", engine.uptime_secs());

    // ---- hot reload: same topology, one more rule added ----
    let mut new_rules = rules();
    new_rules.insert(
        0,
        RuleConfig {
            rule_type: RuleType::DomainSuffix,
            payload: "youtube.com".to_string(),
            outbound: "ss-node".to_string(),
            process_name: None,
        },
    );

    let reloaded = Config {
        outbounds: outbounds(),
        rules: new_rules,
        ..engine.config().clone()
    };
    engine.reload(reloaded)?;
    println!("config reloaded with {} rules", engine.config().rules.len());

    engine.stop()?;
    println!("engine stopped");
    Ok(())
}
