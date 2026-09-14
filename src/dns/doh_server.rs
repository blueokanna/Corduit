//! DNS over HTTPS (DoH) server — RFC 8484, on courierust's server engine.
//!
//! [`courierust::courierust_server::Server`] owns the listener, TLS (with the
//! `h2` + `http/1.1` ALPN offer a DoH client expects), HTTP/1.1 and HTTP/2
//! framing and keep-alive; the handler answers one query at a time against
//! the engine's synchronous resolver.

use crate::common::cancel::CancellationToken;
use crate::dns::error::{DnsError, Result};
use crate::dns::resolver::DnsResolver;
use crate::dns::wire::{BinDecodable, BinEncodable, Message};
use courierust::courierust_body::Body;
use courierust::courierust_http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use courierust::courierust_server::ws::WsConfig;
use courierust::courierust_server::{Handler, Server, ServerConfig, ServerHandle, TlsSettings};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Cap for a POSTed DNS message (a DNS message is at most 65535 bytes).
const MAX_DOH_BODY: usize = 65_536;
/// Cap for a request head: a DoH request carries no interesting headers.
const MAX_DOH_HEAD: usize = 16 * 1024;
/// Read timeout for one request.
const DOH_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// DoH server configuration.
#[derive(Debug, Clone)]
pub struct DohServerConfig {
    /// Listen address.
    pub listen: SocketAddr,
    /// TLS certificate path.
    pub cert_path: String,
    /// TLS private key path.
    pub key_path: String,
    /// DNS query path (default: /dns-query).
    pub path: String,
    /// Enable HTTP/2 (ALPN `h2`; RFC 8484 clients prefer it).
    pub http2: bool,
}

impl Default for DohServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".parse().unwrap(),
            cert_path: String::new(),
            key_path: String::new(),
            path: "/dns-query".to_string(),
            http2: true,
        }
    }
}

/// DNS over HTTPS server.
pub struct DohServer {
    /// Configuration.
    config: DohServerConfig,
    /// DNS resolver.
    resolver: Arc<DnsResolver>,
    /// The running server (bound and serving between `start` and `stop`).
    server: Mutex<Option<ServerHandle>>,
    /// Shutdown signal.
    shutdown: CancellationToken,
}

impl DohServer {
    /// Create a new DoH server.
    pub fn new(config: DohServerConfig, resolver: Arc<DnsResolver>) -> Result<Self> {
        Ok(Self {
            config,
            resolver,
            server: Mutex::new(None),
            shutdown: CancellationToken::new(),
        })
    }

    /// Start the DoH server. Returns once the listener is bound and serving;
    /// blocks until [`Self::stop`] is called.
    pub fn start(&self) -> Result<()> {
        let tls = if !self.config.cert_path.is_empty() && !self.config.key_path.is_empty() {
            Some(
                TlsSettings::from_pem_file(&self.config.cert_path, &self.config.key_path)
                    .map_err(|e| DnsError::Tls(format!("Invalid DoH TLS identity: {e}")))?,
            )
        } else {
            None
        };

        let config = ServerConfig {
            read_timeout: Some(DOH_READ_TIMEOUT),
            max_header_list: MAX_DOH_HEAD,
            max_body: MAX_DOH_BODY,
            http2: self.config.http2,
            // A DoH endpoint serves DNS queries and nothing else: no
            // WebSocket policy, no upgrade path.
            websocket: WsConfig {
                enabled: false,
                ..WsConfig::default()
            },
            tls,
            ..ServerConfig::default()
        };
        let server = Server::bind_with_config(self.config.listen, config)?;
        let addr = server.local_addr()?;
        let handle = server.serve_background(DohHandler {
            resolver: Arc::clone(&self.resolver),
            path: self.config.path.clone(),
        })?;
        info!("DoH server listening on {}", addr);
        *self.server.lock() = Some(handle);

        // Wait for shutdown, then tear the listener down.
        self.shutdown.wait(Duration::from_secs(u64::MAX));
        let handle = self.server.lock().take();
        if let Some(handle) = handle {
            handle.stop();
            let _ = handle.join();
        }
        info!("DoH server stopped");
        Ok(())
    }

    /// Stop the DoH server.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    /// Get the listen address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }
}

/// The RFC 8484 request handler.
struct DohHandler {
    resolver: Arc<DnsResolver>,
    path: String,
}

impl Handler for DohHandler {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        // Compare the *path*: a GET carries the query in `?dns=...`, so the
        // full target never equals the configured path.
        if req.uri.path() != self.path {
            return text_response(StatusCode::NOT_FOUND, "Not Found");
        }

        let result = match req.method {
            Method::GET => handle_get_request(&req, &self.resolver),
            Method::POST => handle_post_request(&req, &self.resolver),
            _ => return text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed"),
        };

        match result {
            Ok(dns_response) => {
                let response_bytes = dns_response.to_bytes().unwrap_or_default();
                let mut resp = Response::with_status(StatusCode::OK);
                resp.headers.insert(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_static("application/dns-message"),
                );
                resp.headers.insert(
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_static("max-age=300"),
                );
                resp.body = Body::from(response_bytes);
                resp
            }
            Err(e) => {
                warn!("DoH query error: {}", e);
                text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("DNS Error: {e}"),
                )
            }
        }
    }
}

/// A plain-text response.
fn text_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut resp = Response::with_status(status);
    resp.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.body = Body::from(message.as_bytes().to_vec());
    resp
}

/// GET handler: base64url-encoded query in `?dns=`.
fn handle_get_request(req: &Request<Body>, resolver: &DnsResolver) -> Result<Message> {
    let query_string = req.uri.query().unwrap_or_default();

    let dns_param = query_string
        .split('&')
        .find_map(|param| {
            let (key, value) = param.split_once('=')?;
            (key == "dns").then_some(value)
        })
        .ok_or_else(|| DnsError::Protocol("Missing 'dns' query parameter".to_string()))?;

    let query_bytes = crate::crypto::codec::base64url_decode(dns_param)
        .ok_or_else(|| DnsError::Protocol("Invalid base64url in 'dns'".to_string()))?;

    process_dns_query(&query_bytes, resolver)
}

/// POST handler: binary DNS message in the body.
fn handle_post_request(req: &Request<Body>, resolver: &DnsResolver) -> Result<Message> {
    let content_type = req
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/dns-message") {
        return Err(DnsError::Protocol(format!(
            "Invalid content-type: {}",
            content_type
        )));
    }

    // The server materialized the body with a hard cap of `MAX_DOH_BODY`.
    let body = req
        .body
        .as_bytes()
        .ok_or_else(|| DnsError::Http("Empty request body".to_string()))?;

    process_dns_query(body, resolver)
}

/// Process a DNS query and generate the response against the synchronous
/// resolver.
fn process_dns_query(query_bytes: &[u8], resolver: &DnsResolver) -> Result<Message> {
    let request = Message::from_bytes(query_bytes)
        .map_err(|e| DnsError::Protocol(format!("Invalid DNS message: {}", e)))?;
    crate::dns::server::process_query(resolver, &request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::config::DnsConfig;
    use courierust::courierust_http::Method;

    #[test]
    fn test_doh_server_config_default() {
        let config = DohServerConfig::default();
        assert_eq!(config.path, "/dns-query");
        assert!(config.http2);
    }

    #[test]
    fn test_doh_server_creation_without_tls() {
        let dns_config = DnsConfig {
            nameservers: vec!["8.8.8.8".to_string()],
            ..Default::default()
        };
        let resolver = Arc::new(DnsResolver::new(dns_config).unwrap());

        let config = DohServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert_path: String::new(),
            key_path: String::new(),
            path: "/dns-query".to_string(),
            http2: true,
        };

        assert!(DohServer::new(config, resolver).is_ok());
    }

    /// A GET request carries its query in `?dns=...`: the route must match on
    /// the path, not on the whole target.
    #[test]
    fn get_request_with_query_matches_the_route() {
        let resolver = Arc::new(DnsResolver::new(DnsConfig::default()).unwrap());
        let handler = DohHandler {
            resolver,
            path: "/dns-query".to_string(),
        };

        let req = Request::new(
            Method::GET,
            "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
        );
        let resp = handler.handle(req);
        // The base64url payload above is a well-formed query, so the route is
        // hit: anything but 404 proves the path comparison works.
        assert_ne!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn other_paths_are_not_found() {
        let resolver = Arc::new(DnsResolver::new(DnsConfig::default()).unwrap());
        let handler = DohHandler {
            resolver,
            path: "/dns-query".to_string(),
        };

        let req = Request::new(
            Method::GET,
            "/other?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
        );
        let resp = handler.handle(req);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }
}
