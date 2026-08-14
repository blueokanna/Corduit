use crate::config::OutboundConfig;
use crate::connection_tracker::global_tracker;
use crate::error::{Error, Result};
use crate::outbound::direct::relay_bidirectional_with_connection;
use crate::outbound::{AsyncReadWrite, OutboundProxy, TargetAddr};
use corduit_crypto::encoding::{encode as b64_encode, Config as B64Config};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// HTTP outbound proxy (HTTP CONNECT tunnel)
pub struct HttpOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

/// Read one line from `reader`, capped at `MAX_LINE` bytes.
///
/// `read_line` has no length limit: a misbehaving proxy that never sends a
/// newline could grow memory without bound (until the caller's timeout). This
/// helper stops as soon as the line is delimited, hits the cap, or hits EOF.
async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<String> {
    const MAX_LINE: usize = 4096;
    let mut line: Vec<u8> = Vec::with_capacity(128);
    loop {
        let buf = reader
            .fill_buf()
            .await
            .map_err(|e| Error::network(format!("Failed to read response line: {e}")))?;
        if buf.is_empty() {
            break; // EOF
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(i) => {
                line.extend_from_slice(&buf[..=i]);
                reader.consume(i + 1);
                break;
            }
            None => {
                let take = MAX_LINE.saturating_sub(line.len()).min(buf.len());
                line.extend_from_slice(&buf[..take]);
                reader.consume(take);
                if line.len() >= MAX_LINE {
                    break;
                }
            }
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Skip HTTP header lines up to a total byte cap, stopping at the blank line.
///
/// Both the number of lines and their sizes are attacker-controlled; without
/// a cap a misbehaving proxy could stream headers without end.
async fn skip_headers<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<()> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut total = 0usize;
    loop {
        let line = read_bounded_line(reader).await?;
        total += line.len();
        if total > MAX_HEADER_BYTES {
            return Err(Error::network("HTTP proxy response headers too large"));
        }
        if line.trim().is_empty() {
            break;
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl OutboundProxy for HttpOutbound {
    async fn connect(&self) -> Result<()> {
        // Test connection to HTTP proxy server
        let addr = format!("{}:{}", self.server, self.port);
        let _stream = TcpStream::connect(&addr).await.map_err(|e| {
            Error::network(format!("Failed to connect to HTTP proxy {}: {}", addr, e))
        })?;
        Ok(())
    }

    async fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    async fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;

        // Parse the test URL to get host and port
        let url = corduit_common::url::Url::parse(test_url)
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

        // Connect to HTTP proxy
        let server_addr = format!("{}:{}", self.server, self.port);
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&server_addr))
            .await
            .map_err(|_| Error::network("Connection timeout"))?
            .map_err(|e| Error::network(format!("Failed to connect: {}", e)))?;

        // Send CONNECT request to establish tunnel
        let target_str = format!("{}:{}", host, url_port);
        let mut connect_request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target_str, target_str
        );

        // Add proxy auth if configured
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            let credentials = format!("{}:{}", user, pass);
            let encoded = b64_encode(credentials.as_bytes(), B64Config::STANDARD);
            connect_request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        connect_request.push_str("\r\n");

        stream
            .write_all(connect_request.as_bytes())
            .await
            .map_err(|e| Error::network(format!("Failed to send CONNECT: {}", e)))?;

        // Read CONNECT response
        let mut reader = BufReader::new(&mut stream);
        let response_line = read_bounded_line(&mut reader).await?;

        if !response_line.contains("200") {
            return Err(Error::network(format!(
                "CONNECT failed: {}",
                response_line.trim()
            )));
        }

        // Skip headers
        skip_headers(&mut reader).await?;

        // Now send HTTP request through the tunnel
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n",
            path, host
        );

        // Get the underlying stream back
        let stream = reader.into_inner();
        stream
            .write_all(http_request.as_bytes())
            .await
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;

        // Read HTTP response
        let result = tokio::time::timeout(timeout, async {
            let mut reader = BufReader::new(stream);
            let response_line = read_bounded_line(&mut reader).await?;

            if response_line.starts_with("HTTP/") {
                Ok(())
            } else {
                Err(Error::network("Invalid HTTP response"))
            }
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(start.elapsed()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::network("Response timeout")),
        }
    }

    async fn relay_tcp(&self, inbound: Box<dyn AsyncReadWrite>, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None).await
    }

    async fn relay_tcp_with_connection(
        &self,
        mut inbound: Box<dyn AsyncReadWrite>,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        // Connect to HTTP proxy
        let server_addr = format!("{}:{}", self.server, self.port);
        let outbound = TcpStream::connect(&server_addr).await.map_err(|e| {
            Error::network(format!(
                "Failed to connect to HTTP proxy {}: {}",
                server_addr, e
            ))
        })?;

        tracing::debug!(
            "HTTP proxy: connected to {} for target {}",
            server_addr,
            target
        );

        // Send CONNECT request
        let target_str = target.to_string();
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            target_str, target_str
        );

        // Add proxy auth if configured
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            let credentials = format!("{}:{}", user, pass);
            let encoded = b64_encode(credentials.as_bytes(), B64Config::STANDARD);
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        request.push_str("\r\n");

        let mut outbound = outbound;
        outbound
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::network(format!("Failed to send CONNECT request: {}", e)))?;

        // Read response
        let mut reader = BufReader::new(&mut outbound);
        let response_line = read_bounded_line(&mut reader).await?;

        // Parse response status
        let parts: Vec<&str> = response_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::protocol("Invalid HTTP proxy response"));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| Error::protocol(format!("Invalid status code: {}", parts[1])))?;

        if status_code != 200 {
            return Err(Error::network(format!(
                "HTTP CONNECT failed with status {}: {}",
                status_code,
                parts.get(2..).map(|p| p.join(" ")).unwrap_or_default()
            )));
        }

        // Skip remaining headers (read until empty line, bounded)
        skip_headers(&mut reader).await?;

        // Get the stream back from the reader
        let outbound = reader.into_inner();
        let mut outbound = outbound;

        tracing::debug!("HTTP proxy: tunnel established to {}", target);

        // Relay data with traffic tracking
        let tracker = global_tracker();
        let result =
            relay_bidirectional_with_connection(&mut inbound, &mut outbound, tracker, connection)
                .await;

        let _ = outbound.shutdown().await;

        result
    }
}

impl HttpOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address"))?
            .clone();

        let port = config.port.ok_or_else(|| Error::config("Missing port"))?;

        let username = config
            .options
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let password = config
            .options
            .get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(Self {
            config,
            server,
            port,
            username,
            password,
        })
    }
}
