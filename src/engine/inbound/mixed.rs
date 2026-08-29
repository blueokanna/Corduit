use crate::engine::config::InboundConfig;
use crate::engine::connection_tracker::{global_tracker, TrackedConnection};
use crate::engine::error::{Error, Result};
use crate::engine::inbound::auth::{
    check_proxy_authorization, socks5_userpass, InboundAuth, SOCKS5_AUTH_USERPASS,
};
use crate::engine::inbound::{bind_tcp_listener, forward, InboundListener};
use crate::engine::outbound::{OutboundManager, TargetAddr};
use crate::engine::routing::Router;
use courierust::courierust_h1 as h1;
use courierust::courierust_http::{
    Body, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
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

/// A pending CONNECT tunnel: the destination and the outbound that will
/// relay it.
struct TunnelJob {
    target: TargetAddr,
    host: String,
    port: u16,
    outbound_tag: String,
}

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
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Result<()> {
        const MAX_HEAD: usize = 64 * 1024;
        const MAX_BODY: usize = 64 * 1024 * 1024;

        // Shared slot for the CONNECT tunnel handoff (handler → loop).
        let tunnel_job: Arc<Mutex<Option<TunnelJob>>> = Arc::new(Mutex::new(None));

        // Keep-alive loop over courierust's H/1 codec (pure functions on the
        // accumulated buffer — the codec's blocking readers do not fit the
        // async stream, so framing is done here).
        loop {
            let Some(req) = read_http_request(&mut stream, MAX_HEAD, MAX_BODY).await? else {
                return Ok(());
            };
            let keep_alive = request_keeps_alive(&req);
            let resp = Self::handle_http_request(
                req,
                peer_addr,
                &router,
                &outbound_manager,
                &auth,
                &tunnel_job,
            )
            .await;
            write_http_response(&mut stream, &resp).await?;

            // CONNECT: the marker response hands the raw stream to the
            // tunnel relay (which blocks for the tunnel's lifetime).
            if resp.headers.contains_key(TUNNEL_MARKER) {
                let job = tunnel_job.lock().unwrap().take();
                if let Some(job) = job {
                    Self::relay_connect_tunnel(stream, job, &router, &outbound_manager).await;
                }
                return Ok(());
            }
            if !keep_alive || response_wants_close(&resp) {
                break;
            }
        }
        Ok(())
    }

    async fn handle_http_request(
        req: Request<Body>,
        peer_addr: SocketAddr,
        router: &Router,
        outbound_manager: &OutboundManager,
        auth: &InboundAuth,
        tunnel_job: &Mutex<Option<TunnelJob>>,
    ) -> Response<Body> {
        let method = req.method.clone();
        let uri = req.uri.as_str().to_string();

        tracing::debug!("HTTP {} {} from {}", method, uri, peer_addr);

        // Enforce configured inbound credentials before serving anything
        // (CWE-306), including CONNECT tunnels.
        if !check_proxy_authorization(&req.headers, auth) {
            tracing::info!("Rejecting unauthenticated HTTP request from {}", peer_addr);
            let mut resp = Response::new(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            resp.headers.insert(
                HeaderName::from_static("proxy-authenticate"),
                HeaderValue::from_static("Basic realm=\"corduit\""),
            );
            resp.body = Body::from(b"Proxy authentication required".to_vec());
            return resp;
        }

        if method == Method::CONNECT {
            return Self::handle_http_connect(req, router, outbound_manager, tunnel_job).await;
        }

        match Self::handle_http_proxy(req, router, outbound_manager).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("HTTP proxy error: {}", e);
                let mut resp = Response::new(StatusCode::BAD_GATEWAY);
                resp.body = Body::from(format!("Proxy error: {e}"));
                resp
            }
        }
    }

    async fn handle_http_connect(
        req: Request<Body>,
        router: &Router,
        outbound_manager: &OutboundManager,
        tunnel_job: &Mutex<Option<TunnelJob>>,
    ) -> Response<Body> {
        let authority = req.uri.as_str();
        let (host, port) = match parse_connect_uri(authority) {
            Some(hp) => hp,
            None => {
                tracing::warn!("Invalid CONNECT URI: {}", authority);
                let mut resp = Response::new(StatusCode::BAD_REQUEST);
                resp.body = Body::from(b"Invalid CONNECT request".to_vec());
                return resp;
            }
        };

        let outbound_tag = router
            .match_outbound(Some(&host), None, Some(port), None)
            .await;
        tracing::info!("CONNECT {}:{} -> {}", host, port, outbound_tag);

        match outbound_manager.get_proxy(&outbound_tag) {
            Some(_proxy) => {}
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                let mut resp = Response::new(StatusCode::BAD_GATEWAY);
                resp.body = Body::from(format!("Outbound '{outbound_tag}' not found"));
                return resp;
            }
        }

        *tunnel_job.lock().unwrap() = Some(TunnelJob {
            target: TargetAddr::new_domain(host.clone(), port),
            host: host.clone(),
            port,
            outbound_tag,
        });

        // 200 OK marks the tunnel as established; the marker header makes
        // the keep-alive loop relay the raw stream.
        let mut resp = Response::new(StatusCode::OK);
        resp.headers.insert(
            HeaderName::from_static(TUNNEL_MARKER),
            HeaderValue::from_static("1"),
        );
        resp
    }

    /// Relay a CONNECT tunnel: push the raw client stream through the
    /// matched outbound with connection tracking.
    async fn relay_connect_tunnel(
        stream: TcpStream,
        job: TunnelJob,
        _router: &Router,
        outbound_manager: &OutboundManager,
    ) {
        let outbound = match outbound_manager.get_proxy(&job.outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", job.outbound_tag);
                return;
            }
        };

        // Resolve the destination IP for display.
        let destination_ip = tokio::net::lookup_host(format!("{}:{}", job.host, job.port))
            .await
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|addr| addr.ip().to_string());

        let tracked_conn = TrackedConnection::new_with_ip(
            "mixed".to_string(),
            job.outbound_tag.clone(),
            job.host.clone(),
            destination_ip,
            job.port,
            "HTTPS".to_string(),
            "tcp".to_string(),
            "HTTP-CONNECT".to_string(),
            format!("{}:{}", job.host, job.port),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);

        if let Err(e) = outbound
            .relay_tcp_with_connection(Box::new(stream), job.target, Some(conn_arc))
            .await
        {
            tracing::debug!("CONNECT relay error via '{}': {}", outbound.tag(), e);
        }
        tracker.untrack(&tracked.id);
    }

    async fn handle_http_proxy(
        req: Request<Body>,
        router: &Router,
        outbound_manager: &OutboundManager,
    ) -> Result<Response<Body>> {
        let (host, port) = parse_http_target(&req)
            .ok_or_else(|| Error::protocol("Invalid HTTP proxy request: missing host"))?;

        let outbound_tag = router
            .match_outbound(Some(&host), None, Some(port), None)
            .await;

        tracing::info!("HTTP {} -> {}", req.uri.as_str(), outbound_tag);

        // Get outbound instance
        let outbound = outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{}' not found", outbound_tag)))?;

        let method = req.method.clone();
        let path = req.uri.as_str().to_string();
        let is_head = method == Method::HEAD;

        let target = TargetAddr::new_domain(host.clone(), port);
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let relay_handle =
            tokio::spawn(async move { outbound.relay_tcp(Box::new(server_side), target).await });

        let (mut read_half, mut write_half) = tokio::io::split(client_side);

        // Re-serialize the request with correct HTTP/1.1 framing: hop-by-hop
        // headers are stripped and the materialized body is re-framed with an
        // explicit Content-Length (CWE-444).
        let body = req.body.as_bytes().map(|b| b.to_vec()).unwrap_or_default();
        forward::send_request(
            &mut write_half,
            &method,
            &path,
            &req.headers,
            &host,
            port,
            &body,
        )
        .await?;

        // Shutdown write side to signal EOF to relay_tcp
        write_half
            .shutdown()
            .await
            .map_err(|e| Error::network(format!("Failed to shutdown write: {}", e)))?;

        // Parse the origin's raw response so it is re-framed correctly for
        // the client (status + headers + de-chunked, size-bounded body).
        let response = forward::read_http_response(&mut read_half, is_head).await?;

        // Cleanup - relay_handle should complete when remote closes connection
        let _ = relay_handle.await;

        Ok(response)
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

/// Marker header set by the CONNECT handler; the keep-alive loop checks it
/// and relays the raw stream (never sent to the client).
const TUNNEL_MARKER: &str = "x-corduit-raw-upgrade";

/// Read one HTTP/1.1 request from the async stream, using courierust's H/1
/// codec (pure functions over the accumulated byte buffer). `None` on a
/// clean close before any byte.
async fn read_http_request(
    stream: &mut TcpStream,
    max_head: usize,
    max_body: usize,
) -> Result<Option<Request<Body>>> {
    let mut buf: Vec<u8> = Vec::new();

    // Accumulate until the head terminator (status line + headers).
    let head_len = loop {
        if let Some(end) = find_subsequence(&buf, b"\r\n\r\n") {
            break end + 4;
        }
        if buf.len() > max_head {
            return Err(Error::protocol("Request head too large"));
        }
        let mut tmp = [0u8; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(60), stream.read(&mut tmp))
            .await
            .map_err(|_| Error::protocol("Timed out reading request head"))?
            .map_err(|e| Error::network(format!("Failed to read request: {e}")))?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(Error::protocol("Connection closed mid-request"));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = &buf[..head_len];
    let mut body_start = head_len;

    // Parse the request line.
    let line_end = head
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| Error::protocol("Malformed request line"))?;
    let req_line = h1::parse_request_line(trim_crlf(&head[..line_end]))
        .map_err(|e| Error::protocol(format!("Malformed request line: {e}")))?;

    // Parse headers (skip the request line).
    let mut headers = HeaderMap::new();
    for raw in head[line_end + 1..head.len() - 4].split(|&b| b == b'\n') {
        let raw = trim_crlf(raw);
        if raw.is_empty() {
            continue;
        }
        let colon = raw
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| Error::protocol("Malformed header line"))?;
        let name = std::str::from_utf8(&raw[..colon])
            .map_err(|_| Error::protocol("Malformed header name"))?
            .trim();
        let value = std::str::from_utf8(&raw[colon + 1..])
            .map_err(|_| Error::protocol("Malformed header value"))?
            .trim();
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| Error::protocol(format!("Invalid header name: {e}")))?;
        let value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| Error::protocol(format!("Invalid header value: {e}")))?;
        headers.append(name, value);
    }

    // Read the body per framing (bytes past the head are already buffered).
    let framing = h1::body_length(&headers, Some(&req_line.method), None)
        .map_err(|e| Error::protocol(format!("Bad body framing: {e}")))?;
    let body = match framing {
        h1::BodyLen::None => Vec::new(),
        h1::BodyLen::Length(n) => {
            if n > max_body {
                return Err(Error::protocol("Request body too large"));
            }
            read_exact_bytes(stream, &mut buf, &mut body_start, n).await?
        }
        h1::BodyLen::Chunked => {
            read_chunked_bytes(stream, &mut buf, &mut body_start, max_body).await?
        }
    };

    Ok(Some(Request {
        method: req_line.method,
        uri: req_line.target,
        version: req_line.version,
        headers,
        body: Body::from(body),
    }))
}

/// Write one HTTP/1.1 response (courierust's H/1 serializer).
async fn write_http_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    resp: &Response<Body>,
) -> Result<()> {
    let mut out = Vec::new();
    let mut headers = resp.headers.clone();
    if !headers.contains_key("content-length") && !headers.contains_key("transfer-encoding") {
        if let Body::Bytes(b) = &resp.body {
            headers.insert(
                HeaderName::from_static("content-length"),
                HeaderValue::from(b.len().to_string()),
            );
        }
    }
    h1::write_response_head(&mut out, resp.status, resp.version, &headers)
        .map_err(|e| Error::protocol(format!("Encode response head: {e}")))?;
    if let Body::Bytes(b) = &resp.body {
        out.extend_from_slice(b);
    }
    stream
        .write_all(&out)
        .await
        .map_err(|e| Error::network(format!("Failed to write response: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::network(format!("Failed to flush response: {e}")))
}

/// Whether the request asks to keep the connection alive.
fn request_keeps_alive(req: &Request<Body>) -> bool {
    match req.headers.get("connection").and_then(|v| v.to_str().ok()) {
        Some(v) if v.eq_ignore_ascii_case("close") => false,
        Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
        _ => req.version == courierust::courierust_http::Version::HTTP_11,
    }
}

/// Whether the response asks to close the connection.
fn response_wants_close(resp: &Response<Body>) -> bool {
    resp.headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("close"))
        .unwrap_or(false)
}

/// Parse a CONNECT authority (`host:port` or `[v6]:port`).
fn parse_connect_uri(authority: &str) -> Option<(String, u16)> {
    let authority = authority.trim_start_matches('/');
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, suffix)) = rest.split_once(']') {
            let port = if let Some(p) = suffix.strip_prefix(':') {
                p.parse::<u16>().ok()?
            } else {
                443
            };
            return Some((host.to_string(), port));
        }
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
        return None;
    }
    if !authority.is_empty() {
        return Some((authority.to_string(), 443));
    }
    None
}

/// Parse an absolute-form HTTP proxy request target or a Host header.
fn parse_http_target(req: &Request<Body>) -> Option<(String, u16)> {
    let target = req.uri.as_str();
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, _) = split_authority_path(rest);
        return split_host_port(authority, 80);
    }
    if let Some(rest) = target.strip_prefix("https://") {
        let (authority, _) = split_authority_path(rest);
        return split_host_port(authority, 443);
    }
    if let Some(host_header) = req.headers.get("host").and_then(|v| v.to_str().ok()) {
        return split_host_port(host_header.trim(), 80);
    }
    None
}

fn split_authority_path(rest: &str) -> (&str, &str) {
    match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let port = if let Some(p) = suffix.strip_prefix(':') {
            p.parse::<u16>().ok()?
        } else {
            default_port
        };
        return Some((host.to_string(), port));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
        return None;
    }
    if authority.is_empty() {
        return None;
    }
    Some((authority.to_string(), default_port))
}

/// Read exactly `n` body bytes (using already-buffered bytes first).
async fn read_exact_bytes(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    start: &mut usize,
    n: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        if *start < buf.len() {
            let take = std::cmp::min(n - out.len(), buf.len() - *start);
            out.extend_from_slice(&buf[*start..*start + take]);
            *start += take;
            continue;
        }
        let mut tmp = [0u8; 2048];
        let read = tokio::time::timeout(std::time::Duration::from_secs(60), stream.read(&mut tmp))
            .await
            .map_err(|_| Error::protocol("Timed out reading body"))?
            .map_err(|e| Error::network(format!("Failed to read body: {e}")))?;
        if read == 0 {
            return Err(Error::protocol("Connection closed mid-body"));
        }
        buf.clear();
        *start = 0;
        buf.extend_from_slice(&tmp[..read]);
    }
    Ok(out)
}

/// Read a chunked request body (using already-buffered bytes first).
async fn read_chunked_bytes(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    start: &mut usize,
    max_body: usize,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        // Chunk-size line.
        let size_line = loop {
            if let Some(pos) = find_subsequence(&buf[*start..], b"\r\n") {
                let pos = *start + pos;
                let line = buf[*start..pos + 2].to_vec();
                *start = pos + 2;
                break line;
            }
            if buf.len() - *start > 1024 {
                return Err(Error::protocol("Chunk size line too long"));
            }
            let mut tmp = [0u8; 2048];
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(60), stream.read(&mut tmp))
                    .await
                    .map_err(|_| Error::protocol("Timed out reading chunk size"))?
                    .map_err(|e| Error::network(format!("Failed to read chunk size: {e}")))?;
            if read == 0 {
                return Err(Error::protocol("Connection closed in chunk size"));
            }
            buf.extend_from_slice(&tmp[..read]);
        };

        let size_str = std::str::from_utf8(
            size_line
                .strip_suffix(b"\r\n")
                .unwrap_or(&size_line)
                .split(|&b| b == b';')
                .next()
                .unwrap_or_default(),
        )
        .map_err(|_| Error::protocol("Invalid chunk size"))?;
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::protocol("Invalid chunk size"))?;

        if size == 0 {
            // Trailer section up to the final CRLF.
            loop {
                if *start + 2 <= buf.len() && &buf[*start..*start + 2] == b"\r\n" {
                    *start += 2;
                    break;
                }
                if let Some(pos) = find_subsequence(&buf[*start..], b"\r\n") {
                    *start += pos + 2;
                    break;
                }
                let mut tmp = [0u8; 2048];
                let read =
                    tokio::time::timeout(std::time::Duration::from_secs(60), stream.read(&mut tmp))
                        .await
                        .map_err(|_| Error::protocol("Timed out reading trailers"))?
                        .map_err(|e| Error::network(format!("Failed to read trailers: {e}")))?;
                if read == 0 {
                    return Err(Error::protocol("Connection closed in trailers"));
                }
                buf.extend_from_slice(&tmp[..read]);
            }
            break;
        }

        if out.len().saturating_add(size) > max_body {
            return Err(Error::protocol("Request body too large"));
        }
        let chunk = read_exact_bytes(stream, buf, start, size).await?;
        out.extend_from_slice(&chunk);
        // Trailing CRLF after the chunk data.
        let mut crlf = [0u8; 2];
        if *start + 2 <= buf.len() {
            *start += 2;
        } else {
            let need = 2 - (buf.len() - *start);
            if *start < buf.len() {
                let have = buf.len() - *start;
                crlf[..have].copy_from_slice(&buf[*start..]);
                *start = buf.len();
            }
            let mut tmp = [0u8; 2];
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(60), stream.read(&mut tmp))
                    .await
                    .map_err(|_| Error::protocol("Timed out reading chunk CRLF"))?
                    .map_err(|e| Error::network(format!("Failed to read chunk CRLF: {e}")))?;
            let _ = need;
            let _ = crlf;
            let _ = read;
        }
    }
    Ok(out)
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Trim a trailing `\r\n` (or lone `\n`).
fn trim_crlf(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}
