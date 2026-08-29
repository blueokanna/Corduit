use crate::common::stream::BoxStream;
use crate::crypto::encoding::{encode as b64_encode, Config as B64Config};
use crate::engine::config::OutboundConfig;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use std::io::{BufReader, Write};
use std::time::Duration;

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
fn read_bounded_line<R: std::io::BufRead>(reader: &mut R) -> Result<String> {
    const MAX_LINE: usize = 4096;
    let mut line: Vec<u8> = Vec::with_capacity(128);
    loop {
        let buf = reader
            .fill_buf()
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
fn skip_headers<R: std::io::BufRead>(reader: &mut R) -> Result<()> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut total = 0usize;
    loop {
        let line = read_bounded_line(reader)?;
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

impl OutboundProxy for HttpOutbound {
    fn connect(&self) -> Result<()> {
        // Test connection to HTTP proxy server
        let _stream =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to HTTP proxy {}:{}: {}",
                    self.server, self.port, e
                ))
            })?;
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;

        // Parse the test URL to get host and port
        let url = crate::common::url::Url::parse(test_url)
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

        // Connect to HTTP proxy (bounded by the socket read/write timeouts below)
        let mut stream = crate::common::socket::connect_host(&self.server, self.port, timeout)
            .map_err(|e| Error::network(format!("Failed to connect: {}", e)))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set read timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set write timeout: {}", e)))?;

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
            .map_err(|e| Error::network(format!("Failed to send CONNECT: {}", e)))?;

        // Read CONNECT response
        let mut reader = BufReader::new(&mut stream);
        let response_line = read_bounded_line(&mut reader)?;

        if !response_line.contains("200") {
            return Err(Error::network(format!(
                "CONNECT failed: {}",
                response_line.trim()
            )));
        }

        // Skip headers
        skip_headers(&mut reader)?;

        // Now send HTTP request through the tunnel
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n",
            path, host
        );

        // Get the underlying stream back
        let stream = reader.into_inner();
        stream
            .write_all(http_request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;

        // Read HTTP response (bounded by the socket read timeout)
        let mut reader = BufReader::new(stream);
        let response_line = read_bounded_line(&mut reader)?;

        if response_line.starts_with("HTTP/") {
            Ok(start.elapsed())
        } else {
            Err(Error::network("Invalid HTTP response"))
        }
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::engine::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        // Connect to HTTP proxy
        let mut outbound =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to HTTP proxy {}:{}: {}",
                    self.server, self.port, e
                ))
            })?;
        outbound
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| Error::network(format!("set read timeout: {}", e)))?;
        outbound
            .set_write_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| Error::network(format!("set write timeout: {}", e)))?;

        tracing::debug!(
            "HTTP proxy: connected to {}:{} for target {}",
            self.server,
            self.port,
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

        outbound
            .write_all(request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send CONNECT request: {}", e)))?;

        // Read response
        let mut reader = BufReader::new(outbound);
        let response_line = read_bounded_line(&mut reader)?;

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
        skip_headers(&mut reader)?;

        // Get the stream back from the reader
        let outbound = reader.into_inner();

        tracing::debug!("HTTP proxy: tunnel established to {}", target);

        // Relay data with traffic tracking
        relay_streams!(inbound, outbound, connection)
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
