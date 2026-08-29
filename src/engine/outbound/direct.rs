//! DIRECT outbound: connect straight to the target.
//!
//! No upstream proxy — this is the baseline every other outbound is compared
//! against. TCP relays run two dedicated copy threads (see
//! [`relay_bidirectional_with_connection`]); UDP is a one-shot request/reply
//! on a fresh socket (immune to Windows ICMP poisoning).

use crate::common::cancel::CancellationToken;
use crate::common::stream::SyncStream;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::ConnectionTracker;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Copy buffer size for the relay threads.
const RELAY_CHUNK: usize = 32 * 1024;

pub struct DirectOutbound {
    config: OutboundConfig,
}

impl OutboundProxy for DirectOutbound {
    fn connect(&self) -> Result<()> {
        // Direct outbound doesn't need to maintain persistent connections
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        // Nothing to disconnect
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        // Direct outbound has no server
        None
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let timeout = Duration::from_secs(30);

        let target_addr = match target {
            TargetAddr::Ip(addr) => *addr,
            TargetAddr::Domain(domain, port) => {
                crate::common::socket::resolve_host(domain, *port, timeout)
                    .map_err(|e| Error::network(format!("Failed to resolve {}: {}", domain, e)))?
                    .into_iter()
                    .next()
                    .ok_or_else(|| Error::network(format!("No address found for {}", domain)))?
            }
        };

        crate::common::socket::udp_exchange(&target_addr, data, timeout, None).map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                Error::network("UDP response timeout")
            } else {
                Error::network(format!("Failed to exchange UDP packet: {}", e))
            }
        })
    }

    fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        // Parse the test URL
        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = Instant::now();

        // Direct connection to target
        let addr = format!("{}:{}", host, url_port);
        let mut stream = crate::common::socket::connect_host(&host, url_port, timeout)
            .map_err(|e| Error::network(format!("Failed to connect to {}: {}", addr, e)))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set read timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set write timeout: {}", e)))?;

        // Send HTTP request
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n",
            path, host
        );
        stream
            .write_all(http_request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;

        // Read the response status line
        let mut reader = std::io::BufReader::new(stream);
        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;

        if response_line.starts_with("HTTP/") {
            Ok(start.elapsed())
        } else {
            Err(Error::network("Invalid HTTP response"))
        }
    }

    fn relay_tcp(
        &self,
        inbound: crate::common::stream::BoxStream,
        target: TargetAddr,
    ) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: crate::common::stream::BoxStream,
        target: TargetAddr,
        connection: Option<Arc<crate::engine::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        use crate::engine::connection_tracker::global_tracker;

        // Connect directly to target
        let target_str = target.to_string();
        let outbound = match target {
            TargetAddr::Ip(addr) => crate::common::socket::connect(&addr, Duration::from_secs(30)),
            TargetAddr::Domain(domain, port) => {
                crate::common::socket::connect_host(&domain, port, Duration::from_secs(30))
            }
        }
        .map_err(|e| Error::network(format!("Direct connect to {} failed: {}", target_str, e)))?;

        // Disable Nagle's algorithm
        outbound.set_nodelay(true).ok();
        outbound
            .set_read_timeout(Some(Duration::from_secs(60)))
            .ok();
        outbound
            .set_write_timeout(Some(Duration::from_secs(60)))
            .ok();

        tracing::debug!("Direct connection to {} established", target_str);

        // Relay data bidirectionally with traffic tracking
        let tracker = global_tracker();
        relay_bidirectional_with_connection(
            inbound,
            Box::new(outbound) as crate::common::stream::BoxStream,
            tracker,
            connection,
            CancellationToken::new(),
        )
    }
}

impl DirectOutbound {
    pub fn new(config: OutboundConfig) -> Self {
        Self { config }
    }
}

/// Bidirectional relay between two owned streams with traffic statistics and
/// optional connection tracking.
///
/// Two dedicated threads, one per direction; EOF half-closes the opposite
/// peer. `a` is the client side (upload), `b` the upstream side (download).
/// Threads need `'static` streams, so both transports are owned (boxed) and
/// shared behind mutexes; each operation locks exactly one stream, which
/// keeps the two-thread relay deadlock-free by construction.
pub fn relay_bidirectional_with_connection(
    a: crate::common::stream::BoxStream,
    b: crate::common::stream::BoxStream,
    tracker: Arc<ConnectionTracker>,
    connection: Option<Arc<crate::engine::connection_tracker::TrackedConnection>>,
    token: CancellationToken,
) -> Result<()> {
    let a = Arc::new(std::sync::Mutex::new(a));
    let b = Arc::new(std::sync::Mutex::new(b));

    // Every shared handle is cloned into each thread's closure so the two
    // relay threads own their own copies (no move-after-move).
    let t1 = {
        let a1 = a.clone();
        let b1 = b.clone();
        let tracker1 = tracker.clone();
        let connection1 = connection.clone();
        let token1 = token.clone();
        std::thread::Builder::new()
            .name("corduit-relay-up".into())
            .spawn(move || {
                let mut buf = vec![0u8; RELAY_CHUNK];
                loop {
                    if token1.is_cancelled() {
                        let _ = a1.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        let _ = b1.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        return Err(Error::network("relay cancelled"));
                    }
                    let n = match a1.lock().unwrap().read(&mut buf) {
                        Ok(0) => {
                            let _ = b1.lock().unwrap().shutdown(std::net::Shutdown::Write);
                            return Ok(());
                        }
                        Ok(n) => n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(e) => {
                            let _ = a1.lock().unwrap().shutdown(std::net::Shutdown::Both);
                            let _ = b1.lock().unwrap().shutdown(std::net::Shutdown::Both);
                            return Err(Error::network(format!("relay read failed: {e}")));
                        }
                    };
                    if let Err(e) = b1.lock().unwrap().write_all(&buf[..n]) {
                        let _ = a1.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        let _ = b1.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        return Err(Error::network(format!("relay write failed: {e}")));
                    }
                    tracker1.add_global_upload(n as u64);
                    if let Some(ref c) = connection1 {
                        c.add_upload(n as u64);
                    }
                }
            })
            .map_err(|e| Error::network(format!("spawn relay thread: {e}")))?
    };

    let t2 = {
        let a2 = a.clone();
        let b2 = b.clone();
        let tracker2 = tracker.clone();
        let connection2 = connection.clone();
        let token2 = token.clone();
        std::thread::Builder::new()
            .name("corduit-relay-down".into())
            .spawn(move || {
                let mut buf = vec![0u8; RELAY_CHUNK];
                loop {
                    if token2.is_cancelled() {
                        let _ = a2.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        let _ = b2.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        return Err(Error::network("relay cancelled"));
                    }
                    let n = match b2.lock().unwrap().read(&mut buf) {
                        Ok(0) => {
                            let _ = a2.lock().unwrap().shutdown(std::net::Shutdown::Write);
                            return Ok(());
                        }
                        Ok(n) => n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        Err(e) => {
                            let _ = a2.lock().unwrap().shutdown(std::net::Shutdown::Both);
                            let _ = b2.lock().unwrap().shutdown(std::net::Shutdown::Both);
                            return Err(Error::network(format!("relay read failed: {e}")));
                        }
                    };
                    if let Err(e) = a2.lock().unwrap().write_all(&buf[..n]) {
                        let _ = a2.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        let _ = b2.lock().unwrap().shutdown(std::net::Shutdown::Both);
                        return Err(Error::network(format!("relay write failed: {e}")));
                    }
                    tracker2.add_global_download(n as u64);
                    if let Some(ref c) = connection2 {
                        c.add_download(n as u64);
                    }
                }
            })
            .map_err(|e| Error::network(format!("spawn relay thread: {e}")))?
    };

    let r1 = t1
        .join()
        .map_err(|_| Error::network("relay thread panicked"))?;
    let r2 = t2
        .join()
        .map_err(|_| Error::network("relay thread panicked"))?;

    if token.is_cancelled() {
        return Err(Error::network("relay cancelled"));
    }

    // One clean direction (EOF) is success; both failing with connection
    // teardown errors is also a normal close.
    match (r1, r2) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(_)) | (Err(_), Ok(())) => Ok(()),
        (Err(e1), Err(e2)) => {
            let normal = |e: &Error| {
                let msg = e.to_string().to_lowercase();
                msg.contains("reset") || msg.contains("broken pipe") || msg.contains("connection")
            };
            if normal(&e1) && normal(&e2) {
                Ok(())
            } else {
                Err(Error::network(format!("Relay error: {} / {}", e1, e2)))
            }
        }
    }
}

/// Bidirectional relay between two streams (without stats).
#[allow(dead_code)]
pub fn relay_bidirectional(
    a: crate::common::stream::BoxStream,
    b: crate::common::stream::BoxStream,
) -> Result<()> {
    let result = relay_bidirectional_with_connection(
        a,
        b,
        crate::engine::connection_tracker::global_tracker(),
        None,
        CancellationToken::new(),
    );
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("reset") || msg.contains("broken pipe") || msg.contains("connection") {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}
