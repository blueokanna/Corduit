use crate::engine::config::{Config, InboundType};
use crate::engine::error::{Error, Result};
use crate::engine::outbound::OutboundManager;
use crate::engine::routing::Router;
use parking_lot::RwLock;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Arc;

mod auth;
mod forward;
mod http;
mod mixed;
mod socks5;

pub use auth::InboundAuth;

use http::HttpInbound;
use mixed::MixedInbound;
use socks5::Socks5Inbound;

fn parse_listen_addr(listen: &str, port: u16) -> Result<SocketAddr> {
    let listen = listen.trim();
    let host = listen
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(listen);
    let ip = host.parse::<IpAddr>().map_err(|error| {
        Error::config_with_source(format!("Invalid inbound listen address '{listen}'"), error)
    })?;
    Ok(SocketAddr::new(ip, port))
}

fn bind_tcp_listener(listen: &str, port: u16, name: &str) -> Result<(TcpListener, SocketAddr)> {
    let addr = parse_listen_addr(listen, port)?;
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .map_err(|error| Error::network(format!("Failed to create {name} socket: {error}")))?;

    socket
        .set_reuse_address(true)
        .map_err(|error| Error::network(format!("Failed to set SO_REUSEADDR: {error}")))?;

    // A wildcard IPv6 listener must also accept the IPv4 loopback traffic used
    // by system-proxy and TUN clients. Explicitly request a dual-stack socket.
    if addr.ip().is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false).map_err(|error| {
            Error::network(format!(
                "Failed to enable dual-stack {name} listener: {error}"
            ))
        })?;
    }

    socket
        .set_nonblocking(true)
        .map_err(|error| Error::network(format!("Failed to set non-blocking: {error}")))?;
    socket.bind(&addr.into()).map_err(|error| {
        Error::network(format!("Failed to bind {name} listener to {addr}: {error}"))
    })?;
    socket
        .listen(1024)
        .map_err(|error| Error::network(format!("Failed to listen on {addr}: {error}")))?;

    let listener: TcpListener = socket.into();
    Ok((listener, addr))
}

/// Inbound connection manager
pub struct InboundManager {
    config: Arc<RwLock<Config>>,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    listeners: RwLock<Vec<Box<dyn InboundListener>>>,
}

/// The synchronous inbound contract: `start` spawns the accept loop(s) and
/// returns once listening; `stop` cancels and joins them.
pub trait InboundListener: Send + Sync {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn tag(&self) -> &str;
}

impl InboundManager {
    pub fn new(
        config: Arc<RwLock<Config>>,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self> {
        let mut listeners: Vec<Box<dyn InboundListener>> = Vec::new();

        {
            let config_read = config.read();
            // Thread the shared credential set into every listener so the
            // configured `general.authentication` is actually enforced.
            let auth = Arc::new(InboundAuth::new(
                config_read.general.authentication.as_deref(),
            ));
            for inbound_config in &config_read.inbounds {
                let listener: Box<dyn InboundListener> = match inbound_config.inbound_type {
                    InboundType::Http => Box::new(HttpInbound::new(
                        inbound_config.clone(),
                        Arc::clone(&router),
                        Arc::clone(&outbound_manager),
                        Arc::clone(&auth),
                    )),
                    InboundType::Socks5 => Box::new(Socks5Inbound::new(
                        inbound_config.clone(),
                        Arc::clone(&router),
                        Arc::clone(&outbound_manager),
                        Arc::clone(&auth),
                    )),
                    InboundType::Mixed => {
                        // Mixed supports both HTTP and SOCKS5 with auto-detection
                        Box::new(MixedInbound::new(
                            inbound_config.clone(),
                            Arc::clone(&router),
                            Arc::clone(&outbound_manager),
                            Arc::clone(&auth),
                        ))
                    }
                    _ => {
                        tracing::warn!(
                            "Unsupported inbound type: {:?}",
                            inbound_config.inbound_type
                        );
                        continue;
                    }
                };
                listeners.push(listener);
            }
        } // config_read is dropped here

        Ok(Self {
            config,
            router,
            outbound_manager,
            listeners: RwLock::new(listeners),
        })
    }

    pub fn start(&self) -> Result<()> {
        for listener in self.listeners.read().iter() {
            listener.start()?;
        }
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        for listener in self.listeners.read().iter() {
            listener.stop()?;
        }
        Ok(())
    }

    /// Rebuild listeners from the current configuration: stop the old set,
    /// construct the new set, then start it.
    pub fn reload(&self) -> Result<()> {
        // Stop existing listeners before swapping so no stale sockets linger.
        for listener in self.listeners.read().iter() {
            let _ = listener.stop();
        }

        let new_listeners = {
            let config_read = self.config.read();
            let auth = Arc::new(InboundAuth::new(
                config_read.general.authentication.as_deref(),
            ));
            let mut new_listeners: Vec<Box<dyn InboundListener>> = Vec::new();
            for inbound_config in &config_read.inbounds {
                let listener: Box<dyn InboundListener> = match inbound_config.inbound_type {
                    InboundType::Http => Box::new(HttpInbound::new(
                        inbound_config.clone(),
                        Arc::clone(&self.router),
                        Arc::clone(&self.outbound_manager),
                        Arc::clone(&auth),
                    )),
                    InboundType::Socks5 => Box::new(Socks5Inbound::new(
                        inbound_config.clone(),
                        Arc::clone(&self.router),
                        Arc::clone(&self.outbound_manager),
                        Arc::clone(&auth),
                    )),
                    InboundType::Mixed => Box::new(MixedInbound::new(
                        inbound_config.clone(),
                        Arc::clone(&self.router),
                        Arc::clone(&self.outbound_manager),
                        Arc::clone(&auth),
                    )),
                    _ => {
                        tracing::warn!(
                            "Unsupported inbound type: {:?}",
                            inbound_config.inbound_type
                        );
                        continue;
                    }
                };
                new_listeners.push(listener);
            }
            new_listeners
        };

        *self.listeners.write() = new_listeners;

        for listener in self.listeners.read().iter() {
            listener.start()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_listen_addr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn parses_ipv4_listen_address() {
        assert_eq!(
            parse_listen_addr("127.0.0.1", 7890).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890)
        );
    }

    #[test]
    fn parses_bracketed_and_unbracketed_ipv6_listen_addresses() {
        let expected = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 7890);
        assert_eq!(parse_listen_addr("::1", 7890).unwrap(), expected);
        assert_eq!(parse_listen_addr("[::1]", 7890).unwrap(), expected);
    }

    #[test]
    fn rejects_non_ip_listen_address() {
        assert!(parse_listen_addr("localhost", 7890).is_err());
    }
}
