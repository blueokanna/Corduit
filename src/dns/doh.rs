//! DNS over HTTPS (DoH) client — RFC 8484, on courierust.
//!
//! The transport is courierust's synchronous HTTP/1.1 + HTTP/2 client
//! (system roots from [`crate::common::roots`]), invoked through
//! `tokio::task::spawn_blocking` so the async engine is never blocked.
//! Both GET (`?dns=` base64url) and POST (binary body) query methods are
//! supported, and every response body is capped at 128 KiB — a DNS message
//! is at most 65535 bytes, so anything larger is a misbehaving server.

use crate::common::roots::system_root_store;
use crate::crypto::encoding::{encode as b64_encode, Config as B64Config};
use crate::dns::error::{DnsError, Result};
use crate::dns::util::random_id;
use crate::dns::wire::{
    BinDecodable, BinEncodable, Message, MessageType, Name, OpCode, Query, RData,
};
use crate::dns::RecordType;
use courierust::courierust_client::{Client, ClientConfig, TlsSettings};
use courierust::courierust_http::uri::Url;
use courierust::courierust_http::{HeaderName, HeaderValue, Method, Request};
use courierust::courierust_tls::TlsVersion;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

/// Hard cap for a single DoH response body (a DNS message is ≤ 65535
/// bytes; anything larger is a hostile or broken server).
const MAX_DOH_RESPONSE: usize = 128 * 1024;

/// DoH request method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DohMethod {
    /// HTTP GET with base64url encoded query.
    Get,
    /// HTTP POST with binary DNS message.
    #[default]
    Post,
}

/// DoH client configuration
#[derive(Debug, Clone)]
pub struct DohClientConfig {
    /// DoH server URL
    pub url: String,
    /// Request method (GET or POST)
    pub method: DohMethod,
    /// Request timeout
    pub timeout: Duration,
    /// Enable HTTP/2
    pub http2: bool,
    /// Custom headers
    pub headers: Vec<(String, String)>,
}

impl Default for DohClientConfig {
    fn default() -> Self {
        Self {
            url: "https://dns.google/dns-query".to_string(),
            method: DohMethod::Post,
            timeout: Duration::from_secs(5),
            http2: true,
            headers: Vec::new(),
        }
    }
}

/// DoH client for DNS resolution.
pub struct DohClient {
    /// Full server URL (scheme, host, path).
    url: String,
    /// courierust blocking HTTP client (own thread pool, TLS via system
    /// roots, HTTP/2 preferred).
    client: Client,
    /// Request method.
    method: DohMethod,
    /// Custom headers.
    headers: Vec<(String, String)>,
}

impl DohClient {
    /// Create a new DoH client with URL.
    pub fn new(url: &str) -> Result<Self> {
        Self::with_config(DohClientConfig {
            url: url.to_string(),
            ..Default::default()
        })
    }

    /// Create a new DoH client with configuration.
    pub fn with_config(config: DohClientConfig) -> Result<Self> {
        // Strict URL validation (courierust's parser rejects bad ports,
        // forbidden authority bytes, and non-http(s) schemes).
        let parsed = Url::parse(&config.url)
            .map_err(|e| DnsError::Config(format!("Invalid DoH URL: {}", e)))?;
        if parsed.scheme != "https" {
            return Err(DnsError::Config("DoH URL must use HTTPS".to_string()));
        }

        let tls = TlsSettings {
            roots: system_root_store().clone(),
            verify: true,
            // DoH benefits from HTTP/2 (one connection, multiplexed
            // queries); fall back to HTTP/1.1 when the server only
            // supports it.
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            now: unix_now(),
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
        };
        let client = Client::with_config(ClientConfig {
            http2: config.http2,
            max_redirects: 3,
            max_body: MAX_DOH_RESPONSE,
            max_header_list: 16 * 1024,
            connect_timeout: Some(config.timeout),
            read_timeout: Some(config.timeout),
            handshake_timeout: Some(config.timeout),
            tls: Some(tls),
            ..Default::default()
        });

        Ok(Self {
            url: config.url,
            client,
            method: config.method,
            headers: config.headers,
        })
    }

    /// Resolve a domain name to IP addresses.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // Try A records first.
        let mut ips = self.query(domain, RecordType::A).await.unwrap_or_default();

        // Also try AAAA records.
        if let Ok(ipv6) = self.query(domain, RecordType::AAAA).await {
            ips.extend(ipv6);
        }

        if ips.is_empty() {
            return Err(DnsError::QueryFailed(format!(
                "No addresses found for {}",
                domain
            )));
        }

        Ok(ips)
    }

    /// Query DNS records.
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let query_bytes = self.build_query(domain, record_type.into())?;
        let response_bytes = self.send_query(&query_bytes).await?;
        self.parse_response(&response_bytes)
    }

    /// Build DNS query message.
    fn build_query(
        &self,
        domain: &str,
        record_type: crate::dns::wire::RecordType,
    ) -> Result<Vec<u8>> {
        let name = Name::from_str(domain)
            .map_err(|e| DnsError::NameError(format!("Invalid domain name: {}", e)))?;

        let mut message = Message::new(random_id(), MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;

        let query = Query::query(name, record_type);
        message.add_query(query);

        message
            .to_vec()
            .map_err(|e| DnsError::Protocol(format!("Failed to serialize query: {}", e)))
    }

    /// Send a DNS query over HTTPS via courierust.
    async fn send_query(&self, query: &[u8]) -> Result<Vec<u8>> {
        let client = self.client.clone();
        let base_url = self.url.clone();
        let method = self.method;
        let headers = self.headers.clone();
        let query = query.to_vec();

        // The per-request timeout is baked into the client config; this
        // closure only performs the blocking round-trip.
        tokio::task::spawn_blocking(move || {
            let mut req = Request::<courierust::courierust_body::Body>::new(Method::POST, "/");
            // RFC 8484 requires these regardless of method.
            req.headers.insert(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("application/dns-message"),
            );
            for (k, v) in &headers {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    req.headers.insert(name, value);
                }
            }

            let url = match method {
                DohMethod::Get => {
                    let encoded = b64_encode(&query, B64Config::URL_SAFE_NO_PAD);
                    let mut u = base_url;
                    u.push(if u.contains('?') { '&' } else { '?' });
                    u.push_str("dns=");
                    u.push_str(&encoded);
                    u
                }
                DohMethod::Post => {
                    req.headers.insert(
                        HeaderName::from_static("content-type"),
                        HeaderValue::from_static("application/dns-message"),
                    );
                    // The client's streaming body type (courierust_body), not
                    // the no_std message body.
                    req.body = courierust::courierust_body::Body::from(query.clone());
                    base_url
                }
            };

            let resp = client.execute(&url, req).map_err(|e| match e.kind {
                courierust::courierust_error::ErrorKind::Timeout => DnsError::Timeout,
                _ => DnsError::Http(format!("DoH request failed: {e}")),
            })?;

            let status = resp.status.as_u16();
            if status != 200 {
                return Err(DnsError::Http(format!(
                    "DoH server returned status {status}"
                )));
            }

            let body = resp
                .body
                .collect_limited(MAX_DOH_RESPONSE)
                .map_err(|e| DnsError::Http(format!("DoH response too large: {e}")))?;
            Ok(body.to_vec())
        })
        .await
        .map_err(|e| DnsError::Http(format!("DoH worker panicked: {e}")))?
    }

    /// Parse DNS response.
    fn parse_response(&self, response: &[u8]) -> Result<Vec<IpAddr>> {
        let message = Message::from_bytes(response)
            .map_err(|e| DnsError::Protocol(format!("Failed to parse DNS response: {}", e)))?;

        let mut ips = Vec::new();

        for answer in &message.answers {
            match &answer.data {
                RData::A(a) => ips.push(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => ips.push(IpAddr::V6(aaaa.0)),
                _ => {}
            }
        }

        trace!("DoH response: {} addresses", ips.len());
        Ok(ips)
    }

    /// Get the DoH server URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// DoH resolver with multiple upstream servers and load balancing.
pub struct DohResolver {
    /// DoH clients.
    clients: Vec<DohClient>,
    /// Current client index (round-robin).
    current: Arc<RwLock<usize>>,
    /// Prefer IPv4 over IPv6.
    prefer_ipv4: bool,
}

impl DohResolver {
    /// Create a new DoH resolver with multiple upstream servers.
    pub fn new(urls: &[String]) -> Result<Self> {
        if urls.is_empty() {
            return Err(DnsError::Config("No DoH servers configured".to_string()));
        }

        let mut clients = Vec::new();
        for url in urls {
            match DohClient::new(url) {
                Ok(client) => {
                    debug!("DoH client created for {}", url);
                    clients.push(client);
                }
                Err(e) => {
                    warn!("Failed to create DoH client for {}: {}", url, e);
                }
            }
        }

        if clients.is_empty() {
            return Err(DnsError::Config(
                "No valid DoH servers configured".to_string(),
            ));
        }

        Ok(Self {
            clients,
            current: Arc::new(RwLock::new(0)),
            prefer_ipv4: true,
        })
    }

    /// Create with custom configuration for each server.
    pub fn with_configs(configs: Vec<DohClientConfig>) -> Result<Self> {
        if configs.is_empty() {
            return Err(DnsError::Config("No DoH servers configured".to_string()));
        }

        let mut clients = Vec::new();
        for config in configs {
            match DohClient::with_config(config.clone()) {
                Ok(client) => {
                    debug!("DoH client created for {}", config.url);
                    clients.push(client);
                }
                Err(e) => {
                    warn!("Failed to create DoH client for {}: {}", config.url, e);
                }
            }
        }

        if clients.is_empty() {
            return Err(DnsError::Config(
                "No valid DoH servers configured".to_string(),
            ));
        }

        Ok(Self {
            clients,
            current: Arc::new(RwLock::new(0)),
            prefer_ipv4: true,
        })
    }

    /// Set IPv4 preference.
    pub fn set_prefer_ipv4(&mut self, prefer: bool) {
        self.prefer_ipv4 = prefer;
    }

    /// Resolve a domain name using round-robin load balancing.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let mut last_error = None;

        // Try each client in round-robin fashion.
        for _ in 0..self.clients.len() {
            let idx = {
                let mut current = self.current.write().await;
                let idx = *current;
                *current = (*current + 1) % self.clients.len();
                idx
            };

            let client = &self.clients[idx];

            match client.resolve(domain).await {
                Ok(mut ips) if !ips.is_empty() => {
                    // Sort by preference.
                    if self.prefer_ipv4 {
                        ips.sort_by_key(|ip| match ip {
                            IpAddr::V4(_) => 0,
                            IpAddr::V6(_) => 1,
                        });
                    }
                    debug!("DoH resolved {} to {:?} via {}", domain, ips, client.url());
                    return Ok(ips);
                }
                Ok(_) => {
                    debug!(
                        "DoH returned empty result for {} via {}",
                        domain,
                        client.url()
                    );
                }
                Err(e) => {
                    debug!(
                        "DoH resolution failed for {} via {}: {}",
                        domain,
                        client.url(),
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::QueryFailed(format!("All DoH servers failed for {}", domain))
        }))
    }

    /// Query specific record type.
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let mut last_error = None;

        for _ in 0..self.clients.len() {
            let idx = {
                let mut current = self.current.write().await;
                let idx = *current;
                *current = (*current + 1) % self.clients.len();
                idx
            };

            let client = &self.clients[idx];

            match client.query(domain, record_type).await {
                Ok(ips) if !ips.is_empty() => {
                    return Ok(ips);
                }
                Ok(_) => continue,
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::QueryFailed(format!(
                "All DoH servers failed for {} {:?}",
                domain, record_type
            ))
        }))
    }
}

/// Current Unix time in seconds (for TLS certificate validity checks).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
