//! The public surface, driven the way a host application drives it.
//!
//! Everything under `src/` is tested from inside `src/`, where the private
//! machinery is in reach. This file can only touch what the crate exports, and
//! that is exactly what the C ABI, the localhost JSON-RPC server and the
//! Flutter host call: [`corduit::api`] for the lifecycle and the DTOs,
//! [`corduit::rpc`] for the shared dispatch table.
//!
//! A change that keeps the engine working while breaking the facade — a lock
//! taken twice, a DTO field nobody fills any more, a spelling a UI cannot
//! match, an error swallowed into a success — fails here and nowhere else.
//!
//! One test, deliberately: the facade owns process-global state (the instance,
//! the runtime proxy mode, the console filter), so the steps below are a single
//! lifecycle and must not interleave with one another.
//!
//! Hermetic: loopback ports only, no upstream server, nothing written outside
//! the test process.

use corduit::api::{
    get_connections, get_connections_dto, get_proxies, get_proxy_groups, get_rules,
    get_traffic_stats_dto, is_proxy_running, select_proxy_in_group, set_log_level, set_proxy_mode,
    start_proxy_from_yaml, stop_proxy,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

/// A port that is free *now*.
///
/// Binding port `0` and dropping the listener leaves the OS free to hand the
/// port to the engine a moment later; the window is small, and the alternative
/// — a hard-coded port — collides on a busy runner.
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("a loopback port")
        .local_addr()
        .expect("a bound address")
        .port()
}

/// The profile the lifecycle test drives: one mixed inbound, a direct outbound,
/// an (unused, never contacted) Shadowsocks node, a selector over both, and a
/// two-rule table.
fn profile(port: u16) -> String {
    format!(
        r#"{{
          "general": {{
            "mode": "rule",
            "mixed_port": {port},
            "bind_address": "127.0.0.1",
            "log_level": "warn"
          }},
          "inbounds": [
            {{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": {port} }}
          ],
          "outbounds": [
            {{ "type": "direct", "tag": "DIRECT" }},
            {{ "type": "shadowsocks", "tag": "ss-node", "server": "127.0.0.1", "port": 8388,
               "password": "test-pass", "cipher": "aes-256-gcm" }},
            {{ "type": "selector", "tag": "PROXY", "outbounds": ["DIRECT", "ss-node"] }}
          ],
          "rules": [
            {{ "type": "domain-suffix", "payload": "example.com", "outbound": "ss-node" }},
            {{ "type": "match", "payload": "", "outbound": "PROXY" }}
          ],
          "rule_providers": [],
          "proxy_providers": []
        }}"#
    )
}

/// A TCP echo server on loopback: whatever is written comes back.
fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("an echo port");
    let addr = listener.local_addr().expect("the echo address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// One SOCKS5 round trip through the engine's mixed inbound to `target`.
///
/// The client is hand-written on purpose: a test that borrowed the crate's own
/// SOCKS5 code would agree with a bug in it.
fn socks5_round_trip(proxy_port: u16, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to the inbound");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout");

    stream.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).expect("greeting reply");
    assert_eq!(
        greeting,
        [0x05, 0x00],
        "the inbound must accept no-auth SOCKS5"
    );

    let SocketAddr::V4(v4) = target else {
        panic!("the echo server is IPv4: {target}")
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).expect("CONNECT");

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).expect("CONNECT reply");
    assert_eq!(
        &reply[..2],
        &[0x05, 0x00],
        "CONNECT must succeed: {reply:?}"
    );

    stream.write_all(payload).expect("payload");
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).expect("echo");
    echoed
}

#[test]
fn the_public_facade_drives_a_full_lifecycle() {
    // The facade must answer before anything is running, too: a UI asks this on
    // startup and an error there is a worse answer than `false`.
    assert!(
        !is_proxy_running().expect("status"),
        "nothing is running yet"
    );
    assert!(
        get_proxies().is_err(),
        "with no engine there are no outbounds to report, and saying so beats an empty list"
    );

    let port = free_port();
    start_proxy_from_yaml(profile(port)).expect("the engine starts from a JSON profile");
    assert!(is_proxy_running().expect("status"));

    let connect = TcpStream::connect(("127.0.0.1", port));
    assert!(
        connect.is_ok(),
        "the mixed inbound must accept on {port}: {connect:?}"
    );
    drop(connect);

    let proxies = get_proxies().expect("outbounds");
    let tags: Vec<&str> = proxies.iter().map(|p| p.tag.as_str()).collect();
    for expected in ["DIRECT", "ss-node", "PROXY"] {
        assert!(tags.contains(&expected), "missing {expected} in {tags:?}");
    }
    let selector = proxies
        .iter()
        .find(|p| p.tag == "PROXY")
        .expect("the group is listed as an outbound");
    assert_eq!(
        selector.protocol_type, "selector",
        "the canonical vocabulary, not the debug name of a Rust variant"
    );

    let groups = get_proxy_groups().expect("groups");
    assert_eq!(groups.len(), 1, "exactly one group was configured");
    let group = &groups[0];
    assert_eq!(group.tag, "PROXY");
    assert_eq!(group.group_type, "selector");
    assert_eq!(group.proxies, vec!["DIRECT", "ss-node"]);

    let rules = get_rules().expect("rules");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].rule_type, "domain-suffix", "{:?}", rules[0]);
    assert_eq!(rules[1].rule_type, "match");
    assert_eq!(rules[1].outbound, "PROXY");
    assert!(select_proxy_in_group("PROXY".to_string(), "ss-node".to_string()).expect("select"));
    assert!(!select_proxy_in_group("missing".to_string(), "DIRECT".to_string()).expect("select"));

    let stats = get_traffic_stats_dto().expect("stats");
    assert_eq!(stats.connection_count, 0, "nothing has connected yet");

    let echo = spawn_echo_server();
    select_proxy_in_group("PROXY".to_string(), "DIRECT".to_string()).expect("select DIRECT");
    let payload: &[u8] = b"the facade relays";
    assert_eq!(
        socks5_round_trip(port, echo, payload),
        payload,
        "the bytes must come back through the engine"
    );

    assert_eq!(
        get_connections().expect("typed connections").len(),
        get_connections_dto().expect("dto connections").len(),
        "the typed list and the DTO list are the same table"
    );

    assert!(
        set_log_level("verbose".to_string()).is_err(),
        "`verbose` is not in the vocabulary"
    );
    set_log_level("debug".to_string()).expect("`debug` is");

    set_proxy_mode(2).expect("direct");
    set_proxy_mode(0).expect("back to the profile's mode");

    let version = corduit::rpc::dispatch("get_version", &nextjson::Value::Null)
        .expect("dispatch get_version");
    assert!(
        version.as_str().is_some_and(|v| !v.is_empty()),
        "get_version returned {version:?}"
    );

    stop_proxy().expect("stop");
    assert!(!is_proxy_running().expect("status"), "stopped");

    stop_proxy().expect("stopping again is a no-op");
    assert!(
        get_proxies().is_err(),
        "with the engine gone the facade says so instead of answering from a stale config"
    );
}
