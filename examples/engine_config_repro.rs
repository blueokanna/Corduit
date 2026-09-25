//! Replays an ArcadiaPlus-exported engine config on the host.
//!
//! ```text
//! cargo run --example engine_config_repro -- <config.json> [node-fragment]
//! ```
//!
//! Initializes and starts the engine with the exported app config, selects
//! the node whose tag contains `node-fragment` inside the main selection
//! group, then idles so the caller can drive traffic through the inbounds.

use std::time::Duration;

const SELECTION_GROUP: &str = "🔰 选择节点";

fn main() {
    let mut args = std::env::args().skip(1);
    let config_path = args
        .next()
        .expect("usage: engine_config_repro <config.json> [node-fragment]");
    let node_fragment = args.next();

    let json = std::fs::read_to_string(&config_path).expect("read config");
    let json = json.replace("\"log_level\":\"info\"", "\"log_level\":\"debug\"");

    corduit::initialize_corduit(json).expect("initialize the engine");
    corduit::start_corduit().expect("start the engine");

    if let Some(fragment) = node_fragment {
        let node = corduit::get_proxies()
            .expect("engine proxies")
            .into_iter()
            .find(|proxy| proxy.tag.contains(&fragment))
            .map(|proxy| proxy.tag)
            .unwrap_or_else(|| panic!("no proxy tag contains '{fragment}'"));
        let switched = corduit::select_proxy_in_group(SELECTION_GROUP.to_string(), node.clone())
            .expect("select the node");
        println!("SELECTED '{node}' via '{SELECTION_GROUP}': {switched}");
    }

    println!("REPRO-RUNNING");
    loop {
        std::thread::sleep(Duration::from_secs(30));
        println!("REPRO-ALIVE");
    }
}
