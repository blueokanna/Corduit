use crate::engine::config::InboundConfig;
use crate::engine::connection_tracker::{global_tracker, TrackedConnection};
use crate::engine::error::{Error, Result};
use crate::engine::inbound::auth::{
    check_proxy_authorization, socks5_userpass, InboundAuth, SOCKS5_AUTH_USERPASS,
};
use crate::engine::inbound::{bind_tcp_listener, InboundListener};
use crate::engine::outbound::{OutboundManager, TargetAddr};
use crate::engine::routing::Router;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// Mixed HTTP/SOCKS5 proxy inbound listener
/// Automatically detects protocol based on first byte
pub struct MixedInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
}

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ADDR_IPV4: u8 = 0x01;
const SOCKS5_ADDR_DOMAIN: u8 = 0x03;
const SOCKS5_ADDR_IPV6: u8 = 0x04;

#[async_trait::async_trait]
impl InboundListener for MixedInbound {
    async fn start(&self) -> Result<()> {
        self.start_listener().await
    }

    async fn stop(&self) -> Result<()> {
        self.stop_listener().await
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
}

impl MixedInbound {
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
            cancel_token: CancellationToken::new(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    async fn start_listener(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                "Mixed inbound already running on {}:{}",
                self.config.listen,
                self.config.port
            );
            return Ok(());
        }

        let (listener, addr) = bind_tcp_listener(&self.config.listen, self.config.port, "Mixed")?;

        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let auth = Arc::clone(&self.auth);
        let cancel_token = self.cancel_token.clone();
        let running = Arc::clone(&self.running);

        running.store(true, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("Mixed inbound on {} shutting down", addr);
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let router = Arc::clone(&router);
                                let outbound_manager = Arc::clone(&outbound_manager);
                                let auth = Arc::clone(&auth);
                                tokio::spawn(async move {
                                    if let Err(err) = Self::handle_connection(stream, peer_addr, router, outbound_manager, auth).await {
                                        tracing::debug!("Mixed connection error from {}: {}", peer_addr, err);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("Mixed accept error: {}", e);
                            }
                        }
                    }
                }
            }
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("Mixed inbound on {} stopped", addr);
        });

        tracing::info!("Mixed inbound (HTTP/SOCKS5) listening on {}", addr);
        Ok(())
    }

    async fn stop_listener(&self) -> Result<()> {
        tracing::info!(
            "Stopping Mixed inbound on {}:{}",
            self.config.listen,
            self.config.port
        );
        self.cancel_token.cancel();

        let mut attempts = 0;
        while self.running.load(std::sync::atomic::Ordering::Relaxed) && attempts < 50 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            attempts += 1;
        }

        Ok(())
    }

    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Result<()> {
        // Peek at first byte to detect protocol
        let mut peek_buf = [0u8; 1];
        stream.peek(&mut peek_buf).await.map_err(|e| {
            Error::network(format!(
                "Failed to peek connection from {}: {}",
                peer_addr, e
            ))
        })?;

        let first_byte = peek_buf[0];

        if first_byte == SOCKS5_VERSION {
            // SOCKS5 protocol
            tracing::debug!("Detected SOCKS5 protocol from {}", peer_addr);
            Self::handle_socks5(stream, peer_addr, router, outbound_manager, auth).await
        } else {
            // Assume HTTP protocol
            tracing::debug!("Detected HTTP protocol from {}", peer_addr);
            Self::handle_http(stream, peer_addr, router, outbound_manager, auth).await
        }
    }

    // ============== HTTP Handling ==============

    async fn handle_http(
        stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Result<()> {
        let io = TokioIo::new(stream);

        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let router = Arc::clone(&router);
            let outbound_manager = Arc::clone(&outbound_manager);
            let auth = Arc::clone(&auth);
            async move {
                Self::handle_http_request(req, peer_addr, router, outbound_manager, auth).await
            }
        });

        if let Err(err) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
        {
            // Filter out common non-error conditions
            let err_str = err.to_string();
            if !err_str.contains("connection closed")
                && !err_str.contains("connection reset")
                && !err_str.contains("broken pipe")
            {
                tracing::debug!("HTTP serve error from {}: {}", peer_addr, err);
            }
        }

        Ok(())
    }

    async fn handle_http_request(
        req: Request<hyper::body::Incoming>,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> std::result::Result<Response<BoxBody<Bytes, std::io::Error>>, std::convert::Infallible>
    {
        let method = req.method().clone();
        let uri = req.uri().clone();

        tracing::debug!("HTTP {} {} from {}", method, uri, peer_addr);

        // Enforce configured inbound credentials before serving anything
        // (CWE-306), including CONNECT tunnels.
        if !check_proxy_authorization(req.headers(), &auth) {
            tracing::info!("Rejecting unauthenticated HTTP request from {}", peer_addr);
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("Proxy-Authenticate", "Basic realm=\"corduit\"")
                .body(
                    Full::new(Bytes::from("Proxy authentication required"))
                        .map_err(|_| std::io::Error::other("body error"))
                        .boxed(),
                )
                .unwrap());
        }

        // Handle CONNECT method for HTTPS tunneling
        if method == Method::CONNECT {
            return Ok(Self::handle_http_connect(req, router, outbound_manager).await);
        }

        // Handle regular HTTP proxy request
        match Self::handle_http_proxy(req, router, outbound_manager).await {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::error!("HTTP proxy error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(
                        Full::new(Bytes::from(format!("Proxy error: {}", e)))
                            .map_err(|_| std::io::Error::other("body error"))
                            .boxed(),
                    )
                    .unwrap())
            }
        }
    }

    async fn handle_http_connect(
        req: Request<hyper::body::Incoming>,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Response<BoxBody<Bytes, std::io::Error>> {
        let uri = req.uri().clone();

        let (host, port) = match Self::parse_connect_uri(&uri) {
            Some(hp) => hp,
            None => {
                tracing::warn!("Invalid CONNECT URI: {}", uri);
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(
                        Full::new(Bytes::from("Invalid CONNECT request"))
                            .map_err(|_| std::io::Error::other("body error"))
                            .boxed(),
                    )
                    .unwrap();
            }
        };

        let outbound_tag = router
            .match_outbound(Some(&host), None, Some(port), None)
            .await;

        tracing::info!("CONNECT {}:{} -> {}", host, port, outbound_tag);

        // Get the outbound proxy
        let outbound = match outbound_manager.get_proxy(&outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(
                        Full::new(Bytes::from(format!(
                            "Outbound '{}' not found",
                            outbound_tag
                        )))
                        .map_err(|_| std::io::Error::other("body error"))
                        .boxed(),
                    )
                    .unwrap();
            }
        };

        // Spawn the relay task using the outbound proxy
        let target = TargetAddr::new_domain(host.clone(), port);
        let outbound_tag_clone = outbound_tag.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let upgraded = TokioIo::new(upgraded);

                    // Try to resolve the destination IP for display
                    let destination_ip = tokio::net::lookup_host(format!("{}:{}", host, port))
                        .await
                        .ok()
                        .and_then(|mut addrs| addrs.next())
                        .map(|addr| addr.ip().to_string());

                    // Track the connection with IP address
                    let tracked_conn = TrackedConnection::new_with_ip(
                        "mixed".to_string(),
                        outbound_tag_clone.clone(),
                        host.clone(),
                        destination_ip,
                        port,
                        "HTTPS".to_string(),
                        "tcp".to_string(),
                        "HTTP-CONNECT".to_string(),
                        format!("{}:{}", host, port),
                    );
                    let tracker = global_tracker();
                    let tracked = tracker.track(tracked_conn);
                    let conn_arc = Arc::clone(&tracked);

                    // Use the outbound proxy to relay traffic with connection tracking
                    if let Err(e) = outbound
                        .relay_tcp_with_connection(Box::new(upgraded), target, Some(conn_arc))
                        .await
                    {
                        tracing::debug!("CONNECT relay error via '{}': {}", outbound.tag(), e);
                    }
                    // Untrack the connection
                    tracker.untrack(&tracked.id);
                }
                Err(e) => {
                    tracing::debug!("HTTP upgrade failed: {}", e);
                }
            }
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(
                Empty::new()
                    .map_err(|_| std::io::Error::other("empty"))
                    .boxed(),
            )
            .unwrap()
    }

    async fn handle_http_proxy(
        req: Request<hyper::body::Incoming>,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
        let uri = req.uri().clone();

        let (host, port) = Self::parse_http_uri(&uri, req.headers())
            .ok_or_else(|| Error::protocol("Invalid HTTP proxy request: missing host"))?;

        let outbound_tag = router
            .match_outbound(Some(&host), None, Some(port), None)
            .await;

        tracing::info!("HTTP {} -> {}", uri, outbound_tag);

        // Get outbound instance
        let outbound = outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        let method = req.method().clone();
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let is_head = method == Method::HEAD;

        let target = TargetAddr::new_domain(host.clone(), port);
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let relay_handle =
            tokio::spawn(async move { outbound.relay_tcp(Box::new(server_side), target).await });

        let (mut read_half, mut write_half) = tokio::io::split(client_side);

        // Re-serialize the request with correct HTTP/1.1 framing: hop-by-hop
        // headers are stripped and any body is re-encoded as chunked (hyper has
        // already decoded the client's framing, so forwarding it verbatim would
        // desync the origin — CWE-444). The body is streamed, never buffered.
        let forwarded_headers = req.headers().clone();
        crate::engine::inbound::forward::send_request(
            &mut write_half,
            &method,
            path,
            &forwarded_headers,
            &host,
            port,
            req.into_body(),
        )
        .await?;

        // Shutdown write side to signal EOF to relay_tcp
        write_half
            .shutdown()
            .await
            .map_err(|e| Error::network(format!("Failed to shutdown write: {}", e)))?;

        // Parse the origin's raw response into a real hyper Response so it is
        // re-framed correctly for the client (status + headers + de-chunked,
        // size-bounded body).
        let response =
            crate::engine::inbound::forward::read_http_response(&mut read_half, is_head).await?;

        // Cleanup - relay_handle should complete when remote closes connection
        let _ = relay_handle.await;

        Ok(response)
    }

    fn parse_connect_uri(uri: &Uri) -> Option<(String, u16)> {
        if let Some(authority) = uri.authority() {
            let host = authority.host().to_string();
            let port = authority.port_u16().unwrap_or(443);
            return Some((host, port));
        }

        // Some clients send path as host:port
        let path = uri.path().trim_start_matches('/');
        if let Some((host, port_str)) = path.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }

        // Try to parse as host:port directly
        let uri_str = uri.to_string();
        if let Some((host, port_str)) = uri_str.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }

        None
    }

    fn parse_http_uri(uri: &Uri, headers: &hyper::HeaderMap) -> Option<(String, u16)> {
        if let Some(host) = uri.host() {
            let port = uri.port_u16().unwrap_or(80);
            return Some((host.to_string(), port));
        }

        if let Some(host_header) = headers.get("host") {
            if let Ok(host_str) = host_header.to_str() {
                if let Some((host, port_str)) = host_str.rsplit_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        return Some((host.to_string(), port));
                    }
                }
                return Some((host_str.to_string(), 80));
            }
        }

        None
    }

    // ============== SOCKS5 Handling ==============

    async fn handle_socks5(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Result<()> {
        const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        let target = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            Self::read_socks5_target(&mut stream, &auth),
        )
        .await
        .map_err(|_| Error::protocol("SOCKS5 handshake timeout"))??;

        // Route the connection
        let outbound_tag = router
            .match_outbound(Some(&target.host()), None, Some(target.port()), None)
            .await;

        tracing::info!("SOCKS5 {} -> {} (from {})", target, outbound_tag, peer_addr);

        // Get the outbound proxy
        let outbound = match outbound_manager.get_proxy(&outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                Self::send_socks5_error(&mut stream, 0x01).await; // General failure
                return Err(Error::config(format!(
                    "Outbound '{}' not found",
                    outbound_tag
                )));
            }
        };

        // Send success response first (with dummy bind address)
        // We don't know the actual bind address yet since we're using outbound proxy
        let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Self::send_socks5_success(&mut stream, dummy_addr).await?;

        // Try to resolve the destination IP for display
        let destination_ip = match &target {
            TargetAddr::Ip(addr) => Some(addr.ip().to_string()),
            TargetAddr::Domain(domain, _) => {
                tokio::net::lookup_host(format!("{}:{}", domain, target.port()))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .map(|addr| addr.ip().to_string())
            }
        };

        // Track the connection with IP address
        let tracked_conn = TrackedConnection::new_with_ip(
            "mixed".to_string(),
            outbound_tag.clone(),
            target.host(),
            destination_ip,
            target.port(),
            "SOCKS5".to_string(),
            "tcp".to_string(),
            "SOCKS5".to_string(),
            target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);

        // Relay data through the outbound proxy with connection tracking
        if let Err(e) = outbound
            .relay_tcp_with_connection(Box::new(stream), target.clone(), Some(conn_arc))
            .await
        {
            tracing::debug!(
                "SOCKS5 relay error via '{}' to {}: {}",
                outbound.tag(),
                target,
                e
            );
        }

        // Untrack the connection
        tracker.untrack(&tracked.id);

        Ok(())
    }

    async fn read_socks5_target(stream: &mut TcpStream, auth: &InboundAuth) -> Result<TargetAddr> {
        let mut header = [0u8; 2];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| Error::protocol(format!("Failed to read SOCKS5 header: {}", e)))?;

        let version = header[0];
        let nmethods = header[1] as usize;

        if version != SOCKS5_VERSION {
            return Err(Error::protocol(format!(
                "Invalid SOCKS version: {} (expected {})",
                version, SOCKS5_VERSION
            )));
        }

        let mut methods = vec![0u8; nmethods];
        stream
            .read_exact(&mut methods)
            .await
            .map_err(|e| Error::protocol(format!("Failed to read SOCKS5 methods: {}", e)))?;

        if auth.required() {
            // Credentials configured: only RFC 1929 user/pass is acceptable.
            if !methods.contains(&SOCKS5_AUTH_USERPASS) {
                stream.write_all(&[SOCKS5_VERSION, 0xFF]).await.ok();
                return Err(Error::protocol(
                    "SOCKS5 client did not offer username/password auth",
                ));
            }
            stream
                .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_USERPASS])
                .await
                .map_err(|e| Error::network(format!("Failed to send auth response: {}", e)))?;
            if !socks5_userpass(stream, auth).await? {
                return Err(Error::protocol("SOCKS5 authentication failed"));
            }
        } else {
            // No credentials configured: NO-AUTH only.
            if !methods.contains(&SOCKS5_AUTH_NONE) {
                stream.write_all(&[SOCKS5_VERSION, 0xFF]).await.ok();
                return Err(Error::protocol("No acceptable SOCKS5 auth methods"));
            }
            stream
                .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])
                .await
                .map_err(|e| Error::network(format!("Failed to send auth response: {}", e)))?;
        }

        let mut request = [0u8; 4];
        stream
            .read_exact(&mut request)
            .await
            .map_err(|e| Error::protocol(format!("Failed to read SOCKS5 request: {}", e)))?;

        let version = request[0];
        let cmd = request[1];
        let atyp = request[3];

        if version != SOCKS5_VERSION {
            return Err(Error::protocol("Invalid SOCKS5 version in request"));
        }

        if cmd != SOCKS5_CMD_CONNECT {
            Self::send_socks5_error(stream, 0x07).await;
            return Err(Error::protocol(format!(
                "Unsupported SOCKS5 command: {}",
                cmd
            )));
        }

        match atyp {
            SOCKS5_ADDR_IPV4 => {
                let mut addr = [0u8; 4];
                stream
                    .read_exact(&mut addr)
                    .await
                    .map_err(|e| Error::protocol(format!("Failed to read IPv4 address: {}", e)))?;
                let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| Error::protocol(format!("Failed to read port: {}", e)))?;
                let port = u16::from_be_bytes(port_buf);
                Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
            }
            SOCKS5_ADDR_DOMAIN => {
                let mut len = [0u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .map_err(|e| Error::protocol(format!("Failed to read domain length: {}", e)))?;
                let mut domain = vec![0u8; len[0] as usize];
                stream
                    .read_exact(&mut domain)
                    .await
                    .map_err(|e| Error::protocol(format!("Failed to read domain: {}", e)))?;
                let domain = String::from_utf8(domain)
                    .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| Error::protocol(format!("Failed to read port: {}", e)))?;
                let port = u16::from_be_bytes(port_buf);
                Ok(TargetAddr::Domain(domain, port))
            }
            SOCKS5_ADDR_IPV6 => {
                let mut addr = [0u8; 16];
                stream
                    .read_exact(&mut addr)
                    .await
                    .map_err(|e| Error::protocol(format!("Failed to read IPv6 address: {}", e)))?;
                let ip = Ipv6Addr::from(addr);
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| Error::protocol(format!("Failed to read port: {}", e)))?;
                let port = u16::from_be_bytes(port_buf);
                Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port)))
            }
            _ => {
                Self::send_socks5_error(stream, 0x08).await;
                Err(Error::protocol(format!(
                    "Unsupported address type: {}",
                    atyp
                )))
            }
        }
    }

    async fn send_socks5_error(stream: &mut TcpStream, error_code: u8) {
        let response = [
            SOCKS5_VERSION,
            error_code,
            0x00, // Reserved
            SOCKS5_ADDR_IPV4,
            0,
            0,
            0,
            0, // Bind address
            0,
            0, // Bind port
        ];
        let _ = stream.write_all(&response).await;
    }

    async fn send_socks5_success(stream: &mut TcpStream, addr: SocketAddr) -> Result<()> {
        let mut response = vec![SOCKS5_VERSION, 0x00, 0x00]; // Success

        match addr.ip() {
            IpAddr::V4(ip) => {
                response.push(SOCKS5_ADDR_IPV4);
                response.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                response.push(SOCKS5_ADDR_IPV6);
                response.extend_from_slice(&ip.octets());
            }
        }

        response.extend_from_slice(&addr.port().to_be_bytes());

        stream
            .write_all(&response)
            .await
            .map_err(|e| Error::network(format!("Failed to send SOCKS5 response: {}", e)))?;

        Ok(())
    }

    // ============== Common Relay ==============

    #[allow(dead_code)]
    async fn relay<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);

        // Use tokio::select with biased to handle both directions properly
        let result = tokio::select! {
            biased;

            result = tokio::io::copy(&mut ar, &mut bw) => {
                let _ = bw.shutdown().await;
                result.map(|_| ())
            }
            result = tokio::io::copy(&mut br, &mut aw) => {
                let _ = aw.shutdown().await;
                result.map(|_| ())
            }
        };

        // Log non-common errors
        if let Err(ref e) = result {
            if e.kind() != std::io::ErrorKind::ConnectionReset
                && e.kind() != std::io::ErrorKind::BrokenPipe
                && !e.to_string().contains("connection")
            {
                tracing::debug!("Relay error: {}", e);
            }
        }

        Ok(())
    }
}
