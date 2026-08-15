//! # rule-provider + proxy-provider (local files)
//!
//! End-to-end provider wiring without any network: writes a small rule file
//! and a proxy subscription into the system temp directory, then starts an
//! engine whose selector group pulls its members from the provider via
//! `use:` (Clash semantics) and whose `rule-set` rule resolves against the
//! rule provider.
//!
//! ```bash
//! cargo run --example providers
//! ```
//!
//! After startup the example prints the live proxy groups (with the
//! provider-expanded members) and switches the group selection to one of the
//! provider nodes.

use corduit::api::{get_proxy_groups, select_proxy, start_proxy_from_yaml, stop_proxy};
use std::path::{Path, PathBuf};

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("corduit-provider-example-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_rule_file(dir: &Path) -> String {
    // `behavior: domain` treats each line as a domain suffix.
    let content = "# domestic domains\nbaidu.com\nqq.com\nexample.cn\n";
    let path = dir.join("domestic.txt");
    std::fs::write(&path, content).expect("write rule file");
    // Forward slashes keep the path valid JSON inside the config document
    // and are accepted by the file APIs on every platform.
    path.to_string_lossy().replace('\\', "/")
}

fn write_subscription(dir: &Path) -> String {
    // Both `{"proxies": [...]}` and a bare array are accepted.
    let content = r#"{
      "proxies": [
        { "type": "shadowsocks", "tag": "sub-jp-01", "server": "10.0.0.1", "port": 8388,
          "password": "demo", "cipher": "aes-256-gcm" },
        { "type": "socks5", "tag": "sub-us-01", "server": "10.0.0.2", "port": 1080 }
      ]
    }"#;
    let path = dir.join("sub.json");
    std::fs::write(&path, content).expect("write subscription");
    // Forward slashes keep the path valid JSON inside the config document.
    path.to_string_lossy().replace('\\', "/")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir();
    let rule_path = write_rule_file(dir.as_path());
    let sub_path = write_subscription(dir.as_path());

    let config = format!(
        r#"{{
      "general": {{ "mode": "rule", "mixed_port": 17893, "bind_address": "127.0.0.1" }},
      "inbounds": [
        {{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 17893 }}
      ],
      "outbounds": [
        {{ "type": "direct", "tag": "DIRECT" }},
        {{ "type": "selector", "tag": "PROXY", "outbounds": ["DIRECT"], "use": ["subscription"] }}
      ],
      "rules": [
        {{ "type": "rule-set", "payload": "domestic", "outbound": "DIRECT" }},
        {{ "type": "match", "payload": "", "outbound": "PROXY" }}
      ],
      "rule_providers": [
        {{ "name": "domestic", "type": "file", "behavior": "domain", "path": "{rule_path}", "interval": 3600 }}
      ],
      "proxy_providers": [
        {{ "name": "subscription", "type": "file", "path": "{sub_path}", "interval": 3600 }}
      ]
    }}"#
    );

    start_proxy_from_yaml(config).await?;

    let groups = get_proxy_groups().await?;
    println!("{} proxy group(s):", groups.len());
    for group in groups {
        println!(
            "  - {} ({}), selected = {}, members = {:?}",
            group.tag, group.group_type, group.selected, group.proxies
        );
    }

    // The `use:` expansion put sub-jp-01 / sub-us-01 into the group; select one.
    select_proxy("PROXY".to_string(), "sub-jp-01".to_string()).await?;
    println!("selected sub-jp-01 in PROXY");

    stop_proxy().await?;

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
