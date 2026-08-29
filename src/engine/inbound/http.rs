//! HTTP proxy inbound on courierust's H/1 codec.
//!
//! The listener is [`crate::common::http_server::HttpServer`]: a blocking
//! H/1 server where each connection runs on its own thread. The synchronous
//! handler bridges into the async engine with a captured
//! `tokio::runtime::Handle`:
//!
//! * plain HTTP proxy requests (absolute-form URI) are forwarded through the
//!   matched outbound with correct re-framing ([`super::forward`]);
//! * CONNECT requests answer `200 OK` and hand the raw connection to the
//!   tunnel handler, which relays it through the outbound.
//!
//! Inbound authentication is enforced on every request (CWE-306) before any
//! proxying happens.

use crate::common::http_server::{RawConnection, TUNNEL_MARKER};
use crate::common::BlockingStream;
use crate::engine::config::InboundConfig;
use crate::engine::connection_tracker::{global_tracker, TrackedConnection};
use crate::engine::error::{Error, Result};
use crate::engine::inbound::auth::{check_proxy_authorization, InboundAuth};
use crate::engine::inbound::forward;
use crate::engine::inbound::InboundListener;
use crate::engine::outbound::{OutboundManager, TargetAddr};
use crate::engine::routing::Router;
use courierust::courierust_http::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

/// HTTP proxy inbound listener.
pub struct HttpInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
    cancel_token: CancellationToken,
    running: Arc<std::sync::atomic::AtomicBool>,
    server: AsyncMutex<Option<crate::common::http_server::HttpServer>>,
}

#[async_trait::async_trait]
impl InboundListener for HttpInbound {
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

impl HttpInbound {
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
            server: AsyncMutex::new(None),
        }
    }

    async fn start_listener(&self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                "HTTP inbound already running on {}:{}",
                self.config.listen,
                self.config.port
            );
            return Ok(());
        }

        let addr = super::parse_listen_addr(&self.config.listen, self.config.port)?;

        let runtime = tokio::runtime::Handle::current();
        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let auth = Arc::clone(&self.auth);

        // Shared slot for the CONNECT tunnel handoff: the handler fills it
        // (target + outbound), the tunnel handler consumes it. Per connection
        // this is strictly sequential (handler then tunnel on the same thread).
        let tunnel_job: Arc<Mutex<Option<TunnelJob>>> = Arc::new(Mutex::new(None));

        let handler = {
            let router = router.clone();
            let outbound_manager = outbound_manager.clone();
            let auth = auth.clone();
            let tunnel_job = tunnel_job.clone();
            let runtime = runtime.clone();
            Arc::new(move |req: Request<Body>| {
                handle_request(
                    req,
                    &router,
                    &outbound_manager,
                    &auth,
                    &runtime,
                    &tunnel_job,
                )
            })
        };

        let tunnel = {
            let router = router.clone();
            let outbound_manager = outbound_manager.clone();
            let tunnel_job = tunnel_job.clone();
            let runtime = runtime.clone();
            Arc::new(move |conn: RawConnection| {
                let Some(job) = tunnel_job.lock().unwrap().take() else {
                    tracing::warn!("CONNECT tunnel handoff without a job");
                    return;
                };
                handle_tunnel(conn, job, &router, &outbound_manager, &runtime);
            })
        };

        let cfg = crate::common::http_server::HttpServerConfig {
            listen: addr,
            tls: None,
            min_version: courierust::courierust_tls::TlsVersion::Tls12,
            max_version: courierust::courierust_tls::TlsVersion::Tls13,
            max_head: 64 * 1024,
            max_body: 64 * 1024 * 1024,
            read_timeout: Some(std::time::Duration::from_secs(300)),
            tunnel_handler: Some(tunnel),
            handler,
        };

        let mut server = crate::common::http_server::HttpServer::bind(cfg)?;
        server.start()?;
        *self.server.lock().await = Some(server);

        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);
        tracing::info!("HTTP inbound listening on {}", addr);
        Ok(())
    }

    async fn stop_listener(&self) -> Result<()> {
        tracing::info!(
            "Stopping HTTP inbound on {}:{}",
            self.config.listen,
            self.config.port
        );
        if let Some(mut server) = self.server.lock().await.take() {
            server.shutdown();
        }
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = self.cancel_token.cancel();
        Ok(())
    }
}

/// A pending CONNECT tunnel: the destination and the outbound that will
/// relay it.
struct TunnelJob {
    target: TargetAddr,
    host: String,
    port: u16,
    outbound_tag: String,
}

/// The synchronous HTTP handler (runs on a server connection thread).
fn handle_request(
    req: Request<Body>,
    router: &Router,
    outbound_manager: &OutboundManager,
    auth: &InboundAuth,
    runtime: &tokio::runtime::Handle,
    tunnel_job: &Mutex<Option<TunnelJob>>,
) -> Response<Body> {
    // Enforce configured inbound credentials before serving anything
    // (CWE-306): without a valid `Proxy-Authorization` the request is
    // rejected with 407, including CONNECT tunnels.
    if !check_proxy_authorization(&req.headers, auth) {
        tracing::info!("Rejecting unauthenticated HTTP request");
        let mut resp = Response::new(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        resp.headers.insert(
            HeaderName::from_static("proxy-authenticate"),
            HeaderValue::from_static("Basic realm=\"corduit\""),
        );
        resp.body = Body::from(b"Proxy authentication required".to_vec());
        return resp;
    }

    if req.method == Method::CONNECT {
        return handle_connect(&req, router, outbound_manager, runtime, tunnel_job);
    }

    match handle_http_proxy(req, router, outbound_manager, runtime) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("HTTP proxy error: {}", e);
            let mut resp = Response::new(StatusCode::BAD_GATEWAY);
            resp.body = Body::from(format!("Proxy error: {e}"));
            resp
        }
    }
}

/// CONNECT: parse the authority, pick an outbound, answer 200 and queue the
/// tunnel job for the tunnel handler.
fn handle_connect(
    req: &Request<Body>,
    router: &Router,
    outbound_manager: &OutboundManager,
    runtime: &tokio::runtime::Handle,
    tunnel_job: &Mutex<Option<TunnelJob>>,
) -> Response<Body> {
    let authority = req.uri.as_str();
    let (host, port) = match parse_authority(authority) {
        Some(hp) => hp,
        None => {
            tracing::warn!("Invalid CONNECT URI: {}", authority);
            return error_response(StatusCode::BAD_REQUEST, "Invalid CONNECT request");
        }
    };

    let outbound_tag = runtime.block_on(async {
        router
            .match_outbound(Some(&host), None, Some(port), None)
            .await
    });
    tracing::info!("CONNECT {}:{} -> {}", host, port, outbound_tag);

    let outbound = match outbound_manager.get_proxy(&outbound_tag) {
        Some(proxy) => proxy,
        None => {
            tracing::error!("Outbound '{}' not found", outbound_tag);
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Outbound '{outbound_tag}' not found"),
            );
        }
    };

    *tunnel_job.lock().unwrap() = Some(TunnelJob {
        target: TargetAddr::new_domain(host.clone(), port),
        host: host.clone(),
        port,
        outbound_tag: outbound.tag().to_string(),
    });

    // 200 OK marks the tunnel as established; the marker header hands the
    // raw connection to the tunnel handler (stripped before sending).
    let mut resp = Response::new(StatusCode::OK);
    resp.headers.insert(
        HeaderName::from_static(TUNNEL_MARKER),
        HeaderValue::from_static("1"),
    );
    resp
}

/// Relay a CONNECT tunnel: bridge the raw client connection into the async
/// world and push it through the matched outbound. Runs on the connection
/// thread for the tunnel's lifetime.
fn handle_tunnel(
    conn: RawConnection,
    job: TunnelJob,
    router: &Router,
    outbound_manager: &OutboundManager,
    runtime: &tokio::runtime::Handle,
) {
    let outbound = match outbound_manager.get_proxy(&job.outbound_tag) {
        Some(proxy) => proxy,
        None => {
            tracing::error!("Outbound '{}' not found", job.outbound_tag);
            return;
        }
    };

    let client = BlockingStream::new(conn, 64, None);
    let target = job.target;
    let host = job.host.clone();
    let port = job.port;

    // Connection tracking.
    let destination_ip = runtime
        .block_on(tokio::net::lookup_host(format!("{host}:{port}")))
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|addr| addr.ip().to_string());
    let tracked_conn = TrackedConnection::new_with_ip(
        "http".to_string(),
        job.outbound_tag.clone(),
        host.clone(),
        destination_ip,
        port,
        "HTTPS".to_string(),
        "tcp".to_string(),
        "HTTP-CONNECT".to_string(),
        format!("{host}:{port}"),
    );
    let tracker = global_tracker();
    let tracked = tracker.track(tracked_conn);
    let conn_arc = Arc::clone(&tracked);
    let tag = job.outbound_tag.clone();
    let _ = router;

    let result = runtime.block_on(async move {
        outbound
            .relay_tcp_with_connection(Box::new(client), target, Some(conn_arc))
            .await
    });

    tracker.untrack(&tracked.id);
    if let Err(e) = result {
        if !e.to_string().contains("connection") {
            tracing::debug!("CONNECT relay error via '{}': {}", tag, e);
        }
    }
}

/// Forward a plain HTTP proxy request (absolute-form URI) through the
/// matched outbound and return the origin's response.
fn handle_http_proxy(
    req: Request<Body>,
    router: &Router,
    outbound_manager: &OutboundManager,
    runtime: &tokio::runtime::Handle,
) -> Result<Response<Body>> {
    let (host, port) = parse_http_target(&req)
        .ok_or_else(|| Error::protocol("Invalid HTTP proxy request: missing host"))?;

    let outbound_tag = runtime.block_on(async {
        router
            .match_outbound(Some(&host), None, Some(port), None)
            .await
    });
    tracing::info!("HTTP {} -> {}", req.uri.as_str(), outbound_tag);

    let outbound = outbound_manager
        .get_proxy(&outbound_tag)
        .ok_or_else(|| Error::config(format!("Outbound '{outbound_tag}' not found")))?;

    let method = req.method.clone();
    let path = req.uri.as_str().to_string();
    let is_head = method == Method::HEAD;

    let target = TargetAddr::new_domain(host.clone(), port);
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let relay_handle =
        tokio::spawn(async move { outbound.relay_tcp(Box::new(server_side), target).await });

    let (mut read_half, mut write_half) = tokio::io::split(client_side);

    // The request body is materialized (bounded); re-serialize it with the
    // hop-by-hop headers stripped and an explicit Content-Length (CWE-444).
    let body = req.body.as_bytes().map(|b| b.to_vec()).unwrap_or_default();
    let body_bytes = std::sync::Arc::new(body);

    runtime.block_on(async {
        forward::send_request(
            &mut write_half,
            &method,
            &path,
            &req.headers,
            &host,
            port,
            &body_bytes,
        )
        .await?;

        write_half
            .shutdown()
            .await
            .map_err(|e| Error::network(format!("Failed to shutdown write: {e}")))?;

        let response = forward::read_http_response(&mut read_half, is_head).await?;
        let _ = relay_handle.await;
        Ok(response)
    })
}

/// Parse a CONNECT authority (`host:port` or `[v6]:port`).
fn parse_authority(authority: &str) -> Option<(String, u16)> {
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
        // Bare IPv6 without brackets is invalid.
        return None;
    }
    if !authority.is_empty() {
        return Some((authority.to_string(), 443));
    }
    None
}

/// Parse an absolute-form HTTP proxy request target (scheme://host[:port]/
/// path or origin-form with a Host header).
fn parse_http_target(req: &Request<Body>) -> Option<(String, u16)> {
    let target = req.uri.as_str();
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, _path) = split_authority_path(rest);
        let (host, port) = split_host_port(authority, 80)?;
        return Some((host, port));
    }
    if let Some(rest) = target.strip_prefix("https://") {
        let (authority, _path) = split_authority_path(rest);
        let (host, port) = split_host_port(authority, 443)?;
        return Some((host, port));
    }
    // Origin-form: rely on the Host header.
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

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut resp = Response::new(status);
    resp.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.body = Body::from(message.as_bytes().to_vec());
    resp
}
