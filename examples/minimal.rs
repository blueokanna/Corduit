//! # Minimal runnable proxy
//!
//! The smallest *real* Corduit instance: one mixed inbound (`127.0.0.1`) plus
//! a `DIRECT` outbound, started and stopped through the typed engine API.
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example minimal
//! ```
//!
//! The listener binds to a high port (`17890` by default) so no root or
//! special privileges are needed. Override with `CORDUIT_PORT` if that port
//! is already taken:
//!
//! ```bash
//! CORDUIT_PORT=18080 cargo run --example minimal
//! ```

use corduit::engine::{
    Config, Corduit, GeneralConfig, InboundConfig, InboundType, OutboundConfig, OutboundType,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("CORDUIT_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(17890);

    // A valid config needs at least one inbound; `Config::default()` alone
    // (empty inbound list) fails validation on purpose.
    let config = Config {
        general: GeneralConfig {
            mixed_port: Some(port),
            bind_address: "127.0.0.1".to_string(),
            mode: corduit::engine::Mode::Rule,
            ..GeneralConfig::default()
        },
        inbounds: vec![InboundConfig {
            inbound_type: InboundType::Mixed,
            tag: "mixed-in".to_string(),
            listen: "127.0.0.1".to_string(),
            port,
            options: Default::default(),
        }],
        outbounds: vec![OutboundConfig {
            outbound_type: OutboundType::Direct,
            tag: "DIRECT".to_string(),
            server: None,
            port: None,
            options: Default::default(),
        }],
        rules: Vec::new(),
        ..Config::default()
    };

    // `Corduit::new` validates the config, installs logging/TLS providers and
    // builds the whole engine (inbounds/outbounds/router/providers).
    let engine = Corduit::new(config).await?;

    // Open the inbound listener. Connections are established lazily, so
    // nothing else is bound until traffic actually flows.
    engine.start().await?;

    println!("proxy running        : {}", engine.is_running().await?);
    println!("listening            : 127.0.0.1:{port}");
    println!("uptime (seconds)     : {}", engine.uptime_secs());

    // Without any rules, Rule mode falls back to the mainland-China
    // auto-direct shortcut; everything here goes DIRECT anyway.
    engine.stop().await?;
    println!("proxy stopped        : {}", !engine.is_running().await?);
    Ok(())
}
