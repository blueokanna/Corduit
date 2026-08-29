//! DNS server implementation (UDP/TCP/DoH/DoT)

use crate::common::cancel::CancellationToken;
use crate::common::exec;
use crate::common::socket;
use crate::dns::config::DnsConfig;
use crate::dns::error::{DnsError, Result};
use crate::dns::resolver::DnsResolver;
use crate::dns::wire::{BinDecodable, BinEncodable, Message, RData, Record, ResponseCode};
use crate::dns::RecordType;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

/// Idle poll interval for the UDP receive loop.
const UDP_POLL: Duration = Duration::from_millis(50);
/// Idle poll interval for the TCP accept loop.
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// DNS server
pub struct DnsServer {
    /// DNS resolver
    resolver: Arc<DnsResolver>,
    /// Configuration
    config: DnsConfig,
    /// Shutdown signal
    shutdown: CancellationToken,
}

impl DnsServer {
    /// Create a new DNS server
    pub fn new(config: DnsConfig) -> Result<Self> {
        let resolver = Arc::new(DnsResolver::new(config.clone())?);

        Ok(Self {
            resolver,
            config,
            shutdown: CancellationToken::new(),
        })
    }

    /// Start the DNS server. Blocks until [`Self::stop`] is called.
    pub fn start(&self) -> Result<()> {
        info!("Starting DNS server on {}", self.config.listen);

        // Start UDP server
        self.start_udp_server()?;

        // Start TCP server if enabled
        if self.config.tcp_enable {
            self.start_tcp_server()?;
        }

        // Wait for shutdown
        self.shutdown.wait(Duration::from_secs(u64::MAX));
        info!("DNS server shutting down");
        Ok(())
    }

    /// Start UDP DNS server on a dedicated receive thread.
    fn start_udp_server(&self) -> Result<()> {
        let udp_socket = Arc::new(socket::udp_bind(self.config.listen, UDP_POLL)?);
        let resolver = self.resolver.clone();
        let shutdown = self.shutdown.clone();

        info!("UDP DNS server listening on {}", self.config.listen);

        std::thread::Builder::new()
            .name("corduit-dns-udp".into())
            .spawn(move || {
                let mut buf = vec![0u8; 4096];

                loop {
                    if shutdown.is_cancelled() {
                        break;
                    }

                    match udp_socket.recv_from(&mut buf) {
                        Ok((len, addr)) => {
                            let data = buf[..len].to_vec();
                            let resolver = resolver.clone();
                            let udp_socket = udp_socket.clone();

                            exec::spawn(move || {
                                if let Err(e) =
                                    handle_udp_query(&udp_socket, &resolver, &data, addr)
                                {
                                    debug!("UDP query error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            // Idle: loop re-checks cancellation.
                        }
                        Err(e) => {
                            error!("UDP recv error: {}", e);
                            // Avoid a tight error loop.
                            shutdown.wait(Duration::from_millis(5));
                        }
                    }
                }
            })
            .map_err(DnsError::Io)?;

        Ok(())
    }

    /// Start TCP DNS server on a dedicated accept thread.
    fn start_tcp_server(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen).map_err(DnsError::Io)?;
        listener.set_nonblocking(true).map_err(DnsError::Io)?;
        let resolver = self.resolver.clone();
        let shutdown = self.shutdown.clone();

        info!("TCP DNS server listening on {}", self.config.listen);

        std::thread::Builder::new()
            .name("corduit-dns-tcp".into())
            .spawn(move || {
                loop {
                    if shutdown.is_cancelled() {
                        break;
                    }

                    match listener.accept() {
                        Ok((stream, addr)) => {
                            // Windows: accepted sockets inherit the
                            // listener's non-blocking mode; switch back so
                            // read timeouts work on the connection.
                            let _ = stream.set_nonblocking(false);
                            let resolver = resolver.clone();

                            exec::spawn(move || {
                                if let Err(e) = handle_tcp_connection(stream, &resolver) {
                                    debug!("TCP connection error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Idle — poll again shortly (also wakes on cancel).
                            shutdown.wait(ACCEPT_POLL);
                        }
                        Err(e) => {
                            error!("TCP accept error: {}", e);
                            shutdown.wait(ACCEPT_POLL);
                        }
                    }
                }
            })
            .map_err(DnsError::Io)?;

        Ok(())
    }

    /// Stop the DNS server
    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    /// Get resolver reference
    pub fn resolver(&self) -> &Arc<DnsResolver> {
        &self.resolver
    }
}

/// Handle UDP DNS query
fn handle_udp_query(
    socket: &UdpSocket,
    resolver: &DnsResolver,
    data: &[u8],
    addr: SocketAddr,
) -> Result<()> {
    let request = Message::from_bytes(data).map_err(|e| DnsError::Protocol(e.to_string()))?;

    let response = process_query(resolver, &request)?;
    let response_data = response
        .to_bytes()
        .map_err(|e| DnsError::Protocol(e.to_string()))?;

    socket.send_to(&response_data, addr).map_err(DnsError::Io)?;
    Ok(())
}

/// Handle TCP DNS connection
fn handle_tcp_connection(mut stream: TcpStream, resolver: &DnsResolver) -> Result<()> {
    const TCP_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    stream
        .set_read_timeout(Some(TCP_QUERY_TIMEOUT))
        .map_err(DnsError::Io)?;
    stream
        .set_write_timeout(Some(TCP_QUERY_TIMEOUT))
        .map_err(DnsError::Io)?;

    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(_) => break,
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            break;
        }

        // Read query
        let mut buf = vec![0u8; len];
        if stream.read_exact(&mut buf).is_err() {
            break;
        }

        let request = Message::from_bytes(&buf).map_err(|e| DnsError::Protocol(e.to_string()))?;
        let response = process_query(resolver, &request)?;
        let response_data = response
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        // Write response with length prefix
        let len = (response_data.len() as u16).to_be_bytes();
        stream.write_all(&len).map_err(DnsError::Io)?;
        stream.write_all(&response_data).map_err(DnsError::Io)?;
    }

    Ok(())
}

/// Process DNS query and generate response.
///
/// Shared by the UDP/TCP servers and the DoH/DoT servers.
pub(crate) fn process_query(resolver: &DnsResolver, request: &Message) -> Result<Message> {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;

    // Copy queries to response
    for query in &request.queries {
        response.add_query(query.clone());
    }

    // Process each query
    for query in &request.queries {
        let name = query.name().to_string();
        let record_type = RecordType::from(query.query_type());

        trace!("DNS query: {} {:?}", name, record_type);

        match resolver.resolve(&name, record_type) {
            Ok(ips) => {
                for ip in ips {
                    let rdata = match ip {
                        IpAddr::V4(v4) => RData::A(crate::dns::wire::rdata::A(v4)),
                        IpAddr::V6(v6) => RData::AAAA(crate::dns::wire::rdata::AAAA(v6)),
                    };

                    let record = Record::from_rdata(
                        query.name().clone(),
                        300, // TTL
                        rdata,
                    );
                    response.add_answer(record);
                }

                if response.answers.is_empty() {
                    response.metadata.response_code = ResponseCode::NXDomain;
                } else {
                    response.metadata.response_code = ResponseCode::NoError;
                }
            }
            Err(e) => {
                warn!("DNS resolution failed for {}: {}", name, e);
                response.metadata.response_code = ResponseCode::ServFail;
            }
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_server_creation() {
        let config = DnsConfig {
            listen: "127.0.0.1:15353".parse().unwrap(),
            nameservers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };

        let server = DnsServer::new(config);
        assert!(server.is_ok());
    }
}
