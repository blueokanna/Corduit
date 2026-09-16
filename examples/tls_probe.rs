//! Minimal TLS client probe: handshake with the courierust TLS stack and
//! send a WebSocket upgrade request, printing exactly what comes back.
//!
//! Usage: `tls_probe [addr] [name]` (default `127.0.0.1:10892 localhost`).

use courierust::courierust_io::{Read as CRead, Write as CWrite};
use courierust::courierust_tls::{ClientConfig, RootStore, TlsConnector, TlsVersion};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:10892".to_string());
    let name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "localhost".to_string());

    let stream = TcpStream::connect(addr).expect("tcp connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_nodelay(true).ok();
    let arc = Arc::new(stream);

    let connector = TlsConnector::new(ClientConfig {
        roots: RootStore::new(),
        verify: false,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        identity: None,
    });

    let mut tls = match connector.connect(&name, arc.clone(), arc.clone()) {
        Ok(t) => t,
        Err(e) => {
            println!("HANDSHAKE-FAIL: {e}");
            return;
        }
    };
    println!(
        "HANDSHAKE-OK version={:?} alpn={:?}",
        tls.version(),
        tls.alpn().map(|a| String::from_utf8_lossy(a).to_string())
    );

    let req = b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    match CWrite::write(&mut tls, req) {
        Ok(n) => println!("REQUEST-WRITTEN {n} bytes"),
        Err(e) => println!("WRITE-ERR: {e}"),
    }
    let _ = CWrite::flush(&mut tls);

    let mut buf = [0u8; 4096];
    for i in 0..3 {
        match CRead::read(&mut tls, &mut buf) {
            Ok(0) => {
                println!("READ#{i}-EOF");
                break;
            }
            Ok(n) => {
                println!("READ#{i} {n} bytes:");
                println!("{}", String::from_utf8_lossy(&buf[..n]));
            }
            Err(e) => {
                println!("READ#{i}-ERR: {e}");
                break;
            }
        }
    }
}
