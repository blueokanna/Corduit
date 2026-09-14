//! Mixed HTTP/SOCKS5 proxy inbound.
//!
//! One listener serves both proxy protocols, and the first byte decides
//! which one a connection is: `0x05` is a SOCKS5 greeting and goes to
//! [`super::socks5::serve_connection`], anything else is HTTP and goes to
//! [`serve_proxy_connection`]. Both branches are the same code the dedicated
//! `socks5` and `http` inbounds run — this module owns the sniffing and the
//! accept loop, nothing else.
//!
//! The sniff *peeks* the byte instead of consuming it, so the protocol
//! handler sees the connection from its first byte.

use crate::common::listener::ConnectionListener;
use crate::engine::config::InboundConfig;
use crate::engine::error::{Error, Result};
use crate::engine::inbound::auth::InboundAuth;
use crate::engine::inbound::http::{
    proxy_server_config, serve_proxy_connection, HttpProxyHandler, PROXY_MAX_CONNECTIONS,
};
use crate::engine::inbound::{bind_tcp_listener, InboundListener};
use crate::engine::outbound::OutboundManager;
use crate::engine::routing::Router;
use courierust::courierust_server::ServerConfig;
use parking_lot::Mutex;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// SOCKS5 version byte — the marker that selects the SOCKS5 branch.
const SOCKS5_VERSION: u8 = 0x05;
/// Budget for the first byte of a connection: a client that connects and
/// then says nothing is dropped.
const SNIFF_TIMEOUT: Duration = Duration::from_secs(60);

/// Mixed HTTP/SOCKS5 proxy inbound listener.
pub struct MixedInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
    running: Arc<AtomicBool>,
    /// The accept loop; each connection is served on its own thread.
    server: Mutex<Option<ConnectionListener>>,
}

impl InboundListener for MixedInbound {
    fn start(&self) -> Result<()> {
        self.start_listener()
    }

    fn stop(&self) -> Result<()> {
        self.stop_listener()
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
}

impl MixedInbound {
    /// Build the inbound. No socket is bound until [`start`](Self::start).
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Self {
        Self {
            config,
            router,
            outbound_manager,
            auth,
            running: Arc::new(AtomicBool::new(false)),
            server: Mutex::new(None),
        }
    }

    fn start_listener(&self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            tracing::warn!(
                "Mixed inbound already running on {}:{}",
                self.config.listen,
                self.config.port
            );
            return Ok(());
        }

        let (listener, addr) = bind_tcp_listener(&self.config.listen, self.config.port, "Mixed")?;

        // The HTTP half is the shared proxy engine; build its handler and
        // server configuration once, per listener.
        let handler = Arc::new(HttpProxyHandler::new(
            "mixed",
            Arc::clone(&self.router),
            Arc::clone(&self.outbound_manager),
            Arc::clone(&self.auth),
        ));
        let server_config = Arc::new(proxy_server_config());
        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let auth = Arc::clone(&self.auth);

        let mut server = ConnectionListener::new(listener, addr, PROXY_MAX_CONNECTIONS);
        server
            .start("corduit-mixed-conn", move |stream, peer| {
                if let Err(e) = dispatch(
                    stream,
                    peer,
                    &router,
                    &outbound_manager,
                    &auth,
                    &handler,
                    &server_config,
                ) {
                    tracing::debug!("Mixed connection from {peer} ended: {e}");
                }
            })
            .map_err(|e| Error::network(format!("Failed to serve Mixed inbound on {addr}: {e}")))?;

        *self.server.lock() = Some(server);
        self.running.store(true, Ordering::Relaxed);
        tracing::info!("Mixed inbound (HTTP/SOCKS5) listening on {addr}");
        Ok(())
    }

    fn stop_listener(&self) -> Result<()> {
        tracing::info!(
            "Stopping Mixed inbound on {}:{}",
            self.config.listen,
            self.config.port
        );
        // Take the listener out first so the lock is released before the
        // (blocking) join of the accept loop.
        let mut server = self.server.lock().take();
        if let Some(server) = server.as_mut() {
            server.stop();
        }
        self.running.store(false, Ordering::Relaxed);
        tracing::info!("Mixed inbound stopped");
        Ok(())
    }
}

/// Send one accepted connection to the protocol its first byte announces.
#[allow(clippy::too_many_arguments)]
fn dispatch(
    stream: TcpStream,
    peer: SocketAddr,
    router: &Arc<Router>,
    outbound_manager: &Arc<OutboundManager>,
    auth: &Arc<InboundAuth>,
    handler: &Arc<HttpProxyHandler>,
    server_config: &Arc<ServerConfig>,
) -> Result<()> {
    // `peek` leaves the byte in place, and the server engines below expect a
    // blocking socket.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(SNIFF_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SNIFF_TIMEOUT));

    let mut first = [0u8; 1];
    let read = stream
        .peek(&mut first)
        .map_err(|e| Error::network(format!("Failed to read from {peer}: {e}")))?;
    if read == 0 {
        return Ok(()); // the peer closed before saying anything
    }

    if first[0] == SOCKS5_VERSION {
        tracing::debug!("Detected SOCKS5 protocol from {peer}");
        super::socks5::serve_connection(
            stream,
            peer,
            Arc::clone(router),
            Arc::clone(outbound_manager),
            Arc::clone(auth),
            "mixed",
        )
    } else {
        tracing::debug!("Detected HTTP protocol from {peer}");
        serve_proxy_connection(stream, handler, server_config)
            .map_err(|e| Error::network(format!("HTTP connection from {peer} failed: {e}")))
    }
}
