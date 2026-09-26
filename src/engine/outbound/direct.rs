//! DIRECT outbound: connect straight to the target.
//!
//! No upstream proxy 鈥?this is the baseline every other outbound is compared
//! against. TCP relays run two dedicated copy threads (see
//! [`relay_bidirectional_with_connection`]); UDP keeps one session per
//! destination: a connected socket plus a reader thread, so a datagram whose
//! peer has nothing to say (QUIC is full of them) cannot stall the flow.

use crate::common::cancel::CancellationToken;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::ConnectionTracker;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr, UdpReplySink};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// How long a DIRECT UDP session may stay silent before it folds.
const DIRECT_UDP_SESSION_IDLE: Duration = Duration::from_secs(120);
/// Read timeout of the session reader between liveness checks.
const DIRECT_UDP_POLL: Duration = Duration::from_secs(30);

pub struct DirectOutbound {
    config: OutboundConfig,
    /// One session per destination; see [`DirectUdpSession`].
    udp_sessions: parking_lot::Mutex<HashMap<String, Arc<DirectUdpSession>>>,
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
        // One datagram's budget; every caller of this one-shot path shares a
        // worker's time, and a UDP peer that has not answered in five seconds
        // is not going to answer this datagram at all.
        let timeout = Duration::from_secs(5);

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

    /// Session-based submission; replies stream back through `sink`.
    fn udp_submit(&self, target: &TargetAddr, data: &[u8], sink: &Arc<UdpReplySink>) -> Result<()> {
        let session = self.udp_session(target)?;
        session.register_sink(sink);
        session.send(data)
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

        let tracker = global_tracker();
        let token = crate::engine::connection_tracker::cancellation_for(connection.as_ref());
        relay_bidirectional_with_connection(
            inbound,
            Box::new(outbound) as crate::common::stream::BoxStream,
            tracker,
            connection,
            token,
        )
    }
}

impl DirectOutbound {
    pub fn new(config: OutboundConfig) -> Self {
        Self {
            config,
            udp_sessions: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// The live session for `target`, created on first use.
    fn udp_session(&self, target: &TargetAddr) -> Result<Arc<DirectUdpSession>> {
        let key = target.to_string();
        if let Some(existing) = self.udp_sessions.lock().get(&key) {
            if existing.alive.load(Ordering::Acquire) {
                return Ok(Arc::clone(existing));
            }
        }

        let resolved = match target {
            TargetAddr::Ip(addr) => *addr,
            TargetAddr::Domain(domain, port) => {
                crate::common::socket::resolve_host(domain, *port, Duration::from_secs(10))
                    .map_err(|e| Error::network(format!("Failed to resolve {domain}: {e}")))?
                    .into_iter()
                    .next()
                    .ok_or_else(|| Error::network(format!("No address found for {domain}")))?
            }
        };

        let socket = crate::common::socket::udp_bind("0.0.0.0:0".parse().unwrap(), DIRECT_UDP_POLL)
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {e}")))?;
        socket
            .connect(resolved)
            .map_err(|e| Error::network(format!("Failed to connect UDP socket: {e}")))?;

        let session = Arc::new(DirectUdpSession {
            socket,
            sinks: parking_lot::Mutex::new(Vec::new()),
            last_active: parking_lot::Mutex::new(Instant::now()),
            alive: AtomicBool::new(true),
            target: target.clone(),
        });

        let reader_session = Arc::clone(&session);
        std::thread::Builder::new()
            .name("corduit-direct-udp".into())
            .spawn(move || pump_direct_udp_replies(reader_session))
            .map_err(|e| Error::network(format!("Failed to spawn the UDP reader: {e}")))?;

        let mut sessions = self.udp_sessions.lock();
        sessions.retain(|_, session| session.alive.load(Ordering::Acquire));
        sessions.insert(key, Arc::clone(&session));
        Ok(session)
    }
}

/// One long-lived DIRECT UDP flow to one destination.
struct DirectUdpSession {
    socket: UdpSocket,
    sinks: parking_lot::Mutex<Vec<Weak<UdpReplySink>>>,
    last_active: parking_lot::Mutex<Instant>,
    alive: AtomicBool,
    target: TargetAddr,
}

impl DirectUdpSession {
    fn register_sink(&self, sink: &Arc<UdpReplySink>) {
        let mut sinks = self.sinks.lock();
        let pointer = Arc::as_ptr(sink);
        sinks.retain(|existing| existing.strong_count() > 0);
        if !sinks
            .iter()
            .any(|existing| std::ptr::eq(existing.as_ptr(), pointer))
        {
            sinks.push(Arc::downgrade(sink));
        }
    }

    fn send(&self, data: &[u8]) -> Result<()> {
        self.socket
            .send(data)
            .map_err(|e| Error::network(format!("UDP send failed: {e}")))?;
        *self.last_active.lock() = Instant::now();
        Ok(())
    }
}

fn pump_direct_udp_replies(session: Arc<DirectUdpSession>) {
    let mut buf = vec![0u8; 65535];
    loop {
        match crate::common::socket::recv_udp_timeout(&session.socket, &mut buf, DIRECT_UDP_POLL) {
            Ok(len) => {
                *session.last_active.lock() = Instant::now();
                let sinks: Vec<Arc<UdpReplySink>> = {
                    let mut guard = session.sinks.lock();
                    let mut live = Vec::with_capacity(guard.len());
                    guard.retain(|weak| match weak.upgrade() {
                        Some(sink) => {
                            live.push(sink);
                            true
                        }
                        None => false,
                    });
                    live
                };
                for sink in sinks {
                    sink.deliver(&session.target, &buf[..len]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                if session.last_active.lock().elapsed() >= DIRECT_UDP_SESSION_IDLE {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!("DIRECT UDP session ended: {e}");
                break;
            }
        }
    }
    session.alive.store(false, Ordering::Release);
}

/// Bidirectional relay between two owned streams with traffic statistics and
/// optional connection tracking.
///
/// Two dedicated threads, one per direction; EOF half-closes the opposite
/// peer. `a` is the client side (upload), `b` the upstream side (download).
/// Threads need `'static` streams, so both transports are owned (boxed) and
/// shared behind mutexes; each operation locks exactly one stream, which
/// keeps the two-thread relay deadlock-free by construction.
///
/// # Lock fairness
///
/// `std::sync::Mutex` handoff is not fair, so an idle direction that polls
/// its source stream with a short read timeout would otherwise starve the
/// opposite direction's writes for seconds (seen on Linux: a 13-byte echo
/// took 2.1 s). When a poll comes back idle (`WouldBlock`/`TimedOut`) each
/// thread therefore drops the source stream's lock and yields for
/// [`RELAY_POLL_YIELD`](crate::common::stream::RELAY_POLL_YIELD) so the other
/// direction can write through within a bounded time.
pub fn relay_bidirectional_with_connection(
    a: crate::common::stream::BoxStream,
    b: crate::common::stream::BoxStream,
    tracker: Arc<ConnectionTracker>,
    connection: Option<Arc<crate::engine::connection_tracker::TrackedConnection>>,
    token: CancellationToken,
) -> Result<()> {
    let upload_tracker = Arc::clone(&tracker);
    let upload_connection = connection.clone();
    let download_tracker = Arc::clone(&tracker);
    let download_connection = connection;

    let accounting = crate::common::stream::RelayAccounting {
        upstream: Some(Arc::new(move |bytes| {
            upload_tracker.add_global_upload(bytes);
            if let Some(ref tracked) = upload_connection {
                tracked.add_upload(bytes);
            }
        })),
        downstream: Some(Arc::new(move |bytes| {
            download_tracker.add_global_download(bytes);
            if let Some(ref tracked) = download_connection {
                tracked.add_download(bytes);
            }
        })),
    };

    if token.is_cancelled() {
        return Err(Error::network("relay cancelled"));
    }

    match crate::common::stream::relay_with(a, b, token.clone(), accounting) {
        Ok(_) => Ok(()),
        Err(error) => {
            if token.is_cancelled() {
                return Err(Error::network("relay cancelled"));
            }
            let message = error.to_string().to_lowercase();
            let teardown = message.contains("reset")
                || message.contains("broken pipe")
                || message.contains("connection")
                || message.contains("not connected");
            if teardown {
                Ok(())
            } else {
                Err(Error::network(format!("Relay error: {error}")))
            }
        }
    }
}
