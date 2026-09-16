//! VMess interoperability probe.
//!
//! Starts the engine with a single rule that sends everything to a VMess
//! outbound, then drives the engine's SOCKS5 inbound against a local
//! reference server (Xray). Modes:
//!
//! ```text
//! tcp      HTTP GET through a `vmess` (AES-128-GCM) outbound on :10888
//! chacha   the same over ChaCha20-Poly1305
//! ws       the same over the WebSocket transport on :10889
//! ws-tls   the same over WebSocket + TLS on :10890 with a self-signed cert
//! tcp-tls  the same over raw TLS on :10893 with a self-signed cert
//! udp      a SOCKS5 UDP ASSOCIATE datagram through the VMess UDP command
//! ```
//!
//! The probe prints what it observed and ends with `PROBE-RESULT=PASS` or
//! `PROBE-RESULT=FAIL`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const UUID: &str = "8c1e7b3a-52d4-4f6b-9d21-3a6f5e8b1c47";
const SOCKS_PORT: u16 = 17890;
const HTTP_TARGET_PORT: u16 = 18080;
const UDP_ECHO_PORT: u16 = 18081;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "tcp".to_string());
    let (server_port, network, cipher, ws_opts) = match mode.as_str() {
        "ws" => (
            10889u16,
            "ws",
            "auto",
            r#","ws-opts":{"path":"/ws","headers":{"Host":"127.0.0.1"}}"#,
        ),
        "ws-tls" => (
            10890u16,
            "ws",
            "auto",
            r#","ws-opts":{"path":"/ws","headers":{"Host":"127.0.0.1"}},"tls":true,"skip-cert-verify":true"#,
        ),
        "tcp-tls" => (
            10893u16,
            "tcp",
            "auto",
            r#","tls":true,"skip-cert-verify":true"#,
        ),
        "chacha" => (10888u16, "tcp", "chacha20-poly1305", ""),
        _ => (10888u16, "tcp", "auto", ""),
    };

    let options_json = format!(
        r#"{{"uuid":"{UUID}","alterId":0,"cipher":"{cipher}","udp":true,"network":"{network}"{ws_opts}}}"#
    );
    let options_field = options_json.replace('"', "\\\"");
    let config = format!(
        r#"{{
  "general": {{"port": 17891, "socks_port": 17892, "mixed_port": 17893, "allow_lan": false, "bind_address": "127.0.0.1", "mode": "rule", "log_level": "debug", "ipv6": false, "tcp_concurrent": false}},
  "dns": {{"enable": false, "listen": "127.0.0.1:5353", "nameservers": [], "fallback": [], "enhanced_mode": "normal"}},
  "inbounds": [{{"inbound_type": "mixed", "tag": "in", "listen": "127.0.0.1", "port": {SOCKS_PORT}, "options": "{{}}"}}],
  "outbounds": [{{"outbound_type": "direct", "tag": "DIRECT", "server": null, "port": null, "options": "{{}}"}},
                {{"outbound_type": "vmess", "tag": "vm", "server": "127.0.0.1", "port": {server_port}, "options": "{options_field}"}}],
  "rules": [{{"rule_type": "match", "payload": "", "outbound": "vm"}}],
  "rule_providers": [],
  "proxy_providers": []
}}"#
    );

    corduit::initialize_corduit(config).expect("the engine accepts the probe config");
    corduit::start_corduit().expect("the engine starts");

    let passed = if mode == "udp" {
        probe_udp_via_socks()
    } else {
        probe_http_via_socks()
    };
    corduit::stop_corduit().ok();
    println!("PROBE-RESULT={}", if passed { "PASS" } else { "FAIL" });
    if !passed {
        std::process::exit(1);
    }
}

/// Open a SOCKS5 control connection to the engine's inbound.
fn socks5_greeting() -> Option<TcpStream> {
    let addr = format!("127.0.0.1:{SOCKS_PORT}");
    let mut stream =
        TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(3)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).ok()?;
    if greeting != [0x05, 0x00] {
        eprintln!("the inbound refused 'no auth': {greeting:?}");
        return None;
    }
    Some(stream)
}

/// `tcp` / `ws` / `chacha`: one HTTP request through a CONNECT tunnel.
fn probe_http_via_socks() -> bool {
    let Some(mut stream) = socks5_greeting() else {
        return false;
    };

    let port = HTTP_TARGET_PORT.to_be_bytes();
    if stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port[0], port[1]])
        .is_err()
    {
        return false;
    }
    let mut reply = [0u8; 10];
    if stream.read_exact(&mut reply).is_err() || reply[1] != 0x00 {
        eprintln!("SOCKS5 CONNECT failed: {reply:?}");
        return false;
    }

    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        eprintln!("reading the response failed");
        return false;
    }
    let text = String::from_utf8_lossy(&response);
    println!("--- response head ---");
    for line in text.lines().take(4) {
        println!("{line}");
    }
    if !(text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200")) {
        eprintln!("unexpected response");
        return false;
    }
    true
}

/// `udp`: SOCKS5 UDP ASSOCIATE, one echoed datagram.
fn probe_udp_via_socks() -> bool {
    let Some(mut ctrl) = socks5_greeting() else {
        return false;
    };

    if ctrl
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .is_err()
    {
        return false;
    }
    let mut head = [0u8; 4];
    if ctrl.read_exact(&mut head).is_err() || head[1] != 0x00 {
        eprintln!("UDP ASSOCIATE failed: {head:?}");
        return false;
    }
    let relay: SocketAddr = match head[3] {
        0x01 => {
            let mut addr = [0u8; 6];
            if ctrl.read_exact(&mut addr).is_err() {
                return false;
            }
            SocketAddr::from((
                [addr[0], addr[1], addr[2], addr[3]],
                u16::from_be_bytes([addr[4], addr[5]]),
            ))
        }
        0x04 => {
            let mut addr = [0u8; 18];
            if ctrl.read_exact(&mut addr).is_err() {
                return false;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&addr[..16]);
            SocketAddr::from((ip, u16::from_be_bytes([addr[16], addr[17]])))
        }
        other => {
            eprintln!("unexpected UDP relay address type: {other}");
            return false;
        }
    };
    println!("udp relay at {relay}");
    // The relay is usually advertised as an unspecified address; RFC 1928
    // says the client substitutes the address it reached the proxy on.
    let relay = if relay.ip().is_unspecified() {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            relay.port(),
        )
    } else {
        relay
    };

    let Ok(udp) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    if udp
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
    {
        return false;
    }

    let port = UDP_ECHO_PORT.to_be_bytes();
    let mut datagram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, port[0], port[1]];
    datagram.extend_from_slice(b"ping");
    if udp.send_to(&datagram, relay).is_err() {
        return false;
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        match udp.recv_from(&mut buf) {
            Ok((n, _)) => {
                let Some(payload) = socks_udp_payload(&buf[..n]) else {
                    continue;
                };
                if payload == b"ping" {
                    println!("udp echo payload verified");
                    return true;
                }
                eprintln!("unexpected udp payload: {payload:?}");
                return false;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) => {
                eprintln!("udp receive failed: {e}");
                return false;
            }
        }
    }
    eprintln!("the udp echo never came back");
    false
}

/// Strip the SOCKS5 UDP envelope (`RSV RSV FRAG ATYP ADDR PORT`) and return
/// the payload.
fn socks_udp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 5 || packet[2] != 0 {
        return None;
    }
    match packet[3] {
        0x01 => (packet.len() >= 10).then(|| &packet[10..]),
        0x03 => {
            let length = packet[4] as usize;
            (packet.len() >= 7 + length).then(|| &packet[7 + length..])
        }
        0x04 => (packet.len() >= 22).then(|| &packet[22..]),
        _ => None,
    }
}
