//! DNS over HTTPS (DoH) server — RFC 8484, on courierust.
//!
//! The HTTP/1.1 server is [`crate::common::http_server::HttpServer`]
//! (courierust's H/1 codec + TLS). The synchronous handler answers each DoH
//! request directly against the engine's synchronous DNS resolver on a
//! dedicated server thread.

use crate::common::cancel::CancellationToken;
use crate::common::http_server::{error_response, HttpServer, HttpServerConfig, TlsIdentity};
use crate::crypto::encoding::{decode as b64_decode, Config as B64Config};
use crate::dns::error::{DnsError, Result};
use crate::dns::resolver::DnsResolver;
use crate::dns::wire::{BinDecodable, BinEncodable, Message};
use courierust::courierust_http::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
};
use courierust::courierust_tls::TlsVersion;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

/// Cap for a POSTed DNS message (a DNS message is at most 65535 bytes).
const MAX_DOH_BODY: usize = 65_536;

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
    /// Enable HTTP/2.
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
    /// The underlying blocking HTTP server (bound lazily in `start`).
    server: Mutex<Option<HttpServer>>,
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

    /// Start the DoH server. Returns after the server is bound and
    /// listening; blocks until [`Self::stop`] is called.
    pub fn start(&self) -> Result<()> {
        let tls = if !self.config.cert_path.is_empty() && !self.config.key_path.is_empty() {
            Some(TlsIdentity::from_pem_files(
                &self.config.cert_path,
                &self.config.key_path,
            )?)
        } else {
            None
        };

        let resolver = self.resolver.clone();
        let path = self.config.path.clone();

        let handler = Arc::new(move |req: Request<Body>| handle_request(req, &resolver, &path));

        let cfg = HttpServerConfig {
            listen: self.config.listen,
            tls,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            max_head: 16 * 1024,
            max_body: MAX_DOH_BODY,
            read_timeout: Some(std::time::Duration::from_secs(30)),
            tunnel_handler: None,
            handler,
        };

        let mut server = HttpServer::bind(cfg)?;
        server.start()?;
        info!("DoH server listening on {}", server.local_addr()?);
        *self.server.lock() = Some(server);

        // Wait for shutdown, then tear the listener down.
        self.shutdown.wait(std::time::Duration::from_secs(u64::MAX));
        let server = self.server.lock().take();
        if let Some(mut s) = server {
            s.shutdown();
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

/// The HTTP handler: validates the path and method, decodes the DNS query,
/// resolves it through the engine's synchronous resolver and returns the DNS
/// response.
fn handle_request(
    req: Request<Body>,
    resolver: &DnsResolver,
    expected_path: &str,
) -> Response<Body> {
    if req.uri.as_str() != expected_path {
        return error_response(StatusCode::NOT_FOUND, "Not Found");
    }

    let result = match req.method {
        Method::GET => handle_get_request(&req, resolver),
        Method::POST => handle_post_request(&req, resolver),
        _ => {
            return error_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        }
    };

    match result {
        Ok(dns_response) => {
            let response_bytes = dns_response.to_bytes().unwrap_or_default();
            let mut resp = Response::new(StatusCode::OK);
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
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("DNS Error: {e}"),
            )
        }
    }
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

    let query_bytes = b64_decode(dns_param.as_bytes(), B64Config::URL_SAFE_NO_PAD)
        .map_err(|e| DnsError::Protocol(format!("Invalid base64: {:?}", e)))?;

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

    // The server already materialized the body with a hard cap; pull the
    // bytes out for the resolver.
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

        let server = DohServer::new(config, resolver);
        assert!(server.is_ok());
    }
}
