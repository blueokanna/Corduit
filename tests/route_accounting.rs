use corduit::engine::config::Config;
use corduit::engine::connection_tracker::global_tracker;
use corduit::engine::outbound::{OutboundManager, TargetAddr, UdpReplySink};
use parking_lot::RwLock;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, mpsc};
use std::time::Duration;

fn echo(mut socket: TcpStream) {
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = [0u8; 4096];
    while let Ok(n) = socket.read(&mut bytes) {
        if n == 0 || socket.write_all(&bytes[..n]).is_err() {
            break;
        }
    }
}

#[test]
fn leaf_accounting_survives_short_connections_and_counts_groups_once() {
    let tracker = global_tracker();
    tracker.reset();
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = destination.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            echo(destination.accept().unwrap().0);
        }
    });
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_port = socks.local_addr().unwrap().port();
    let proxy = std::thread::spawn(move || {
        let (mut stream, _) = socks.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).unwrap();
        let mut request = [0; 10];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 1]);
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        echo(stream);
    });
    let config: Config = nextjson::from_str(&format!(
        r#"{{
        "outbounds": [
          {{"type":"direct","tag":"DIRECT"}},
          {{"type":"socks5","tag":"REMOTE","server":"127.0.0.1","port":{socks_port}}},
          {{"type":"selector","tag":"GROUP","outbounds":["DIRECT","REMOTE"]}},
          {{"type":"selector","tag":"GLOBAL","outbounds":["REMOTE"]}}
        ],
        "rules": [{{"type":"match","outbound":"DIRECT"}}]
    }}"#
    ))
    .unwrap();
    use corduit::engine::routing::{Router, proxy_mode, set_runtime_proxy_mode};
    struct ResetMode;
    impl Drop for ResetMode {
        fn drop(&mut self) {
            set_runtime_proxy_mode(proxy_mode::CONFIG);
        }
    }
    let _reset_mode = ResetMode;
    let config = Arc::new(RwLock::new(config));
    let router = Router::new(Arc::clone(&config)).unwrap();
    let manager = OutboundManager::new(config).unwrap();
    set_runtime_proxy_mode(proxy_mode::RULE);
    assert_eq!(
        router.match_outbound(None, Some(target.ip()), Some(target.port()), None),
        "DIRECT"
    );
    set_runtime_proxy_mode(proxy_mode::GLOBAL);
    let global = router.match_outbound(None, Some(target.ip()), Some(target.port()), None);
    assert_eq!(global, "GLOBAL");
    let payload = vec![0x5a; 16384];
    for tag in ["DIRECT", "GROUP", global.as_str()] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let inbound = listener.accept().unwrap().0;
        let outbound = manager.get_proxy(tag).unwrap();
        let relay = std::thread::spawn(move || {
            outbound.relay_tcp(Box::new(inbound), TargetAddr::Ip(target))
        });
        client.write_all(&payload).unwrap();
        let mut reply = vec![0; payload.len()];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, payload);
        client.shutdown(Shutdown::Both).unwrap();
        drop(client);
        relay.join().unwrap().unwrap();
    }
    server.join().unwrap();
    proxy.join().unwrap();
    let size = payload.len() as u64;
    assert_eq!(tracker.route_totals(), (size * 2, size * 2, size, size));
    assert_eq!(tracker.total_upload(), size * 3);
    assert_eq!(tracker.total_download(), size * 3);

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let address = udp.local_addr().unwrap();
    let responder = std::thread::spawn(move || {
        let mut data = [0; 1024];
        let (len, source) = udp.recv_from(&mut data).unwrap();
        udp.send_to(&data[..len], source).unwrap();
    });
    let (tx, rx) = mpsc::channel();
    let sink = UdpReplySink::new(move |_, data| {
        tx.send(data.to_vec()).unwrap();
    });
    manager
        .get_proxy("GROUP")
        .unwrap()
        .udp_submit(&TargetAddr::Ip(address), b"udp payload", &sink)
        .unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        b"udp payload"
    );
    responder.join().unwrap();
    assert_eq!(
        tracker.route_totals(),
        (size * 2 + 11, size * 2 + 11, size, size)
    );
    tracker.reset();
    assert_eq!(tracker.route_totals(), (0, 0, 0, 0));
}

/// Explicit opt-in: exercises the same core on a real desktop network without
/// changing system routes/proxy settings or reading any user subscription.
#[test]
#[ignore = "requires an external network and curl"]
fn domestic_https_through_rule_mode() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let config: Config = nextjson::from_str(&format!(
        r##"{{
      "general": {{"mode":"rule","log_level":"warn","ipv6":false,"tcp_concurrent":true}},
      "dns": {{"enable":true,"listen":"127.0.0.1:0", "nameservers":[
        "https://223.5.5.5/dns-query",
        "https://223.6.6.6/dns-query"
      ]}},
      "inbounds":[{{"type":"socks5","tag":"probe","listen":"127.0.0.1","port":{port}}}],
      "outbounds":[{{"type":"direct","tag":"DIRECT"}},{{"type":"reject","tag":"REJECT"}}],
      "rules":[
        {{"type":"domain-suffix","payload":"bilibili.com","outbound":"DIRECT"}},
        {{"type":"domain-suffix","payload":"qq.com","outbound":"DIRECT"}},
        {{"type":"match","outbound":"REJECT"}}
      ]
    }}"##
    ))
    .unwrap();
    let engine = corduit::Corduit::new(config).unwrap();
    engine.start().unwrap();
    struct Stop(corduit::Corduit);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.stop();
        }
    }
    let _stop = Stop(engine);
    global_tracker().reset();
    for url in [
        "https://www.bilibili.com/",
        "https://api.bilibili.com/x/web-interface/search/type?search_type=video&keyword=rust",
        "https://weixin.qq.com/",
    ] {
        let output = std::process::Command::new(if cfg!(windows) { "curl.exe" } else { "curl" })
            .args([
                "--silent",
                "--show-error",
                "--noproxy",
                "",
                "--socks5-hostname",
                &format!("127.0.0.1:{port}"),
                "--connect-timeout",
                "10",
                "--max-time",
                "20",
                "--output",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
                "--write-out",
                "%{http_code} %{time_total}",
                url,
            ])
            .output()
            .unwrap();
        println!(
            "rule/DIRECT {url}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.starts_with(b"000"));
    }
    let (up, down, proxy_up, proxy_down) = global_tracker().route_totals();
    assert!(up > 0 && down > 0);
    assert_eq!((proxy_up, proxy_down), (0, 0));
}
