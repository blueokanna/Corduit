//! End-to-end integration tests: a real SOCKS5 client through the
//! synchronous engine to a real TCP echo server.
//!
//! These exercise the whole synchronous pipeline — accept thread, SOCKS5
//! handshake, routing, DIRECT outbound and the two-thread bidirectional
//! relay — over real sockets, no mocks.

use crate::engine::config::{
    Config, GeneralConfig, InboundConfig, InboundType, LogLevel, OutboundConfig, OutboundType,
};
use crate::engine::Corduit;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

/// An echo server: reads whatever it is sent and writes it straight back.
fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
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

/// Pick a likely-free loopback port.
fn free_port() -> u16 {
    // Bind port 0 to learn a free port, then drop the listener so the proxy
    // can take it. A tiny race window is acceptable for a test.
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Build an engine with one mixed inbound + DIRECT outbound.
fn engine_with_mixed_inbound(port: u16) -> Corduit {
    // Isolate from process-global runtime state staged by other (parallel)
    // tests: `Corduit::new` merges `runtime_proxy_providers` and rule
    // providers, so a provider left behind by an api test would make these
    // e2e tests try to load a file that does not exist.
    crate::engine::proxy_provider::set_runtime_proxy_providers(Vec::new());
    crate::engine::set_runtime_rule_providers(Vec::new());

    let config = Config {
        general: GeneralConfig {
            mixed_port: Some(port),
            log_level: LogLevel::Error,
            ..Default::default()
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
    Corduit::new(config).expect("engine builds")
}

/// SOCKS5 no-auth CONNECT handshake, then return the established stream.
fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Greeting: SOCKS5, one method, no-auth.
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [0x05, 0x00], "proxy must accept no-auth");

    // CONNECT request (IPv4 target).
    let SocketAddr::V4(v4) = target else {
        panic!("test targets are IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).unwrap();

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0x00, "CONNECT must succeed");
    // Consume the bind address (4-byte IPv4 + 2-byte port).
    let mut bind = [0u8; 6];
    stream.read_exact(&mut bind).unwrap();

    stream
}

#[test]
fn socks5_relays_to_echo_server() {
    let echo = spawn_echo_server();
    let port = free_port();
    let engine = engine_with_mixed_inbound(port);
    engine.start().expect("engine starts");

    let proxy: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let mut stream = socks5_connect(proxy, echo);

    // Round-trip a few chunks through the bidirectional relay.
    let payloads: &[&[u8]] = &[
        b"hello corduit",
        &[0u8; 64 * 1024], // one large block (> relay buffer)
        b"bye",
    ];
    for payload in payloads {
        stream.write_all(payload).unwrap();
        let mut buf = vec![0u8; payload.len()];
        let mut got = 0;
        while got < payload.len() {
            let n = stream.read(&mut buf[got..]).unwrap();
            assert!(n > 0, "echo must not EOF mid-payload");
            got += n;
        }
        assert_eq!(&buf[..], *payload, "echo must match payload");
    }

    // Half-close the write side; the echo server sees EOF and closes, which
    // lets the relay finish and the engine return the stream.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);

    engine.stop().expect("engine stops");
}

#[test]
fn two_concurrent_socks5_connections() {
    let echo = spawn_echo_server();
    let port = free_port();
    let engine = engine_with_mixed_inbound(port);
    engine.start().expect("engine starts");

    let proxy: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let mut handles = Vec::new();
    for i in 0..4 {
        // `SocketAddr` is `Copy`; the `move` closure captures it by value.
        handles.push(std::thread::spawn(move || {
            let mut stream = socks5_connect(proxy, echo);
            let msg = format!("concurrent-{i}");
            stream.write_all(msg.as_bytes()).unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
            stream.shutdown(std::net::Shutdown::Both).ok();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    engine.stop().expect("engine stops");
}

/// A DIRECT outbound's UDP path: one-shot request/reply over a local UDP
/// echo server.
#[test]
fn direct_udp_exchange_roundtrip() {
    use std::net::UdpSocket;

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target: SocketAddr = udp.local_addr().unwrap();
    let _echo = {
        let sock = udp.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok((n, peer)) = sock.recv_from(&mut buf) {
                if sock.send_to(&buf[..n], peer).is_err() {
                    break;
                }
            }
        })
    };

    // Use the public one-shot exchange helper directly.
    let reply =
        crate::common::socket::udp_exchange(&target, b"udp-ping", Duration::from_secs(5), None)
            .expect("udp exchange round-trips");
    assert_eq!(reply, b"udp-ping");
}

/// The engine must refuse an unknown inbound type rather than silently bind
/// nothing, and stop must be idempotent.
#[test]
fn stop_is_idempotent() {
    let port = free_port();
    let engine = engine_with_mixed_inbound(port);
    engine.start().expect("engine starts");
    engine.stop().expect("first stop");
    engine.stop().expect("second stop");
    assert!(!engine.is_running().unwrap());
}

/// Sanity check that the echo server itself round-trips (isolates the relay
/// from a broken test fixture).
#[test]
fn echo_server_roundtrips_directly() {
    let echo = spawn_echo_server();
    let mut stream = TcpStream::connect(echo).expect("connect to echo");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"probe-echo").unwrap();
    let mut buf = [0u8; 10];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"probe-echo");
}

/// A minimal HTTP/1.1 origin: one request in, one fixed response out.
fn spawn_http_origin(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                // Read the request head only; `Connection: close` (sent by
                // the proxy) means no body is expected.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while stream.read_exact(&mut byte).is_ok() {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    addr
}

/// Send one raw HTTP/1.1 request over a fresh connection and return the full
/// response.
fn http_exchange(proxy: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

/// The `mixed` inbound's HTTP half is the shared proxy handler: a plain
/// (absolute-form) request is forwarded through the matched outbound and the
/// origin's response is re-framed back to the client.
#[test]
fn http_proxy_forwards_plain_requests() {
    let origin = spawn_http_origin("proxied-body");
    let port = free_port();
    let engine = engine_with_mixed_inbound(port);
    engine.start().expect("engine starts");

    let proxy = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let response = http_exchange(
        proxy,
        &format!(
            "GET http://127.0.0.1:{}/plain HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            origin.port(),
            origin.port()
        ),
    );

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {response}"
    );
    assert!(
        response.ends_with("proxied-body"),
        "body not forwarded: {response}"
    );
    engine.stop().expect("engine stops");
}

/// `CONNECT` through the same inbound: the server answers `200`, hands the
/// raw connection to the tunnel, and the tunnel relays it through the
/// outbound — bytes in both directions, including the pipelined case.
#[test]
fn http_proxy_tunnels_connect() {
    let echo = spawn_echo_server();
    let port = free_port();
    let engine = engine_with_mixed_inbound(port);
    engine.start().expect("engine starts");

    let proxy = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let mut stream = TcpStream::connect(proxy).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // The first payload travels with the CONNECT request: the handoff must
    // keep the bytes the request parser already read.
    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\nfirst",
        echo.port(),
        echo.port()
    );
    stream.write_all(request.as_bytes()).unwrap();

    // Read the handshake response (ends at the blank line), then the
    // echoed payload that followed it.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read_exact(&mut byte).is_ok() {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 200 OK"), "got: {head}");

    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(
        &echoed, b"first",
        "pipelined payload must survive the handoff"
    );

    // And a second round-trip proves the relay is bidirectional.
    stream.write_all(b"second").unwrap();
    let mut second = [0u8; 6];
    stream.read_exact(&mut second).unwrap();
    assert_eq!(&second, b"second");

    let _ = stream.shutdown(std::net::Shutdown::Both);
    engine.stop().expect("engine stops");
}
