use crate::common::stream::BoxStream;
use crate::engine::config::OutboundConfig;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::time::Duration;

/// SOCKS5 outbound proxy
pub struct Socks5Outbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl OutboundProxy for Socks5Outbound {
    fn connect(&self) -> Result<()> {
        let _stream =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to SOCKS5 server {}:{}: {}",
                    self.server, self.port, e
                ))
            })?;
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        // SOCKS5 outbound doesn't maintain persistent connections
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        let probe = crate::common::http_probe::HttpProbe::new(test_url, timeout)?;
        let tcp = crate::common::socket::connect_host(&self.server, self.port, probe.remaining()?)
            .map_err(|e| Error::network(format!("Probe connect failed: {e}")))?;
        let mut transport = probe.transport(&tcp);
        self.perform_handshake(&mut transport)?;
        self.send_connect_request_target(
            &mut transport,
            &TargetAddr::Domain(probe.url.host.clone(), probe.url.port),
        )?;
        self.read_connect_response(&mut transport)?;
        probe.finish(&tcp)
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
        // Connect to SOCKS5 server
        let mut outbound =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to SOCKS5 server {}:{}: {}",
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
            "SOCKS5: connected to {}:{} for target {}",
            self.server,
            self.port,
            target
        );

        // Perform SOCKS5 handshake
        self.perform_handshake(&mut outbound)?;

        // Send CONNECT request with domain support
        self.send_connect_request_target(&mut outbound, &target)?;

        // Read response
        self.read_connect_response(&mut outbound)?;

        tracing::debug!("SOCKS5: tunnel established to {}", target);

        // Relay data with traffic tracking
        relay_streams!(inbound, outbound, connection)
    }
}

impl Socks5Outbound {
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

        match (&username, &password) {
            (None, None) => {}
            (Some(user), Some(pass))
                if (1..=255).contains(&user.len()) && (1..=255).contains(&pass.len()) => {}
            _ => {
                return Err(Error::config(
                    "SOCKS5 credentials must be supplied together, each 1..=255 bytes",
                ));
            }
        }

        Ok(Self {
            config,
            server,
            port,
            username,
            password,
        })
    }

    fn perform_handshake<S: Read + Write>(&self, stream: &mut S) -> Result<()> {
        // SOCKS5 initial handshake
        let handshake = if self.username.is_some() {
            // Explicit credentials must not silently downgrade to no authentication.
            vec![0x05, 0x01, 0x02]
        } else {
            vec![0x05, 0x01, 0x00] // No auth only
        };

        stream
            .write_all(&handshake)
            .map_err(|e| Error::network(format!("Failed to send SOCKS5 handshake: {}", e)))?;

        // Read response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).map_err(|e| {
            Error::network(format!("Failed to read SOCKS5 handshake response: {}", e))
        })?;

        if response[0] != 0x05 {
            return Err(Error::protocol("Invalid SOCKS5 version in response"));
        }

        match response[1] {
            0x00 if self.username.is_none() => Ok(()),
            0x00 => Err(Error::protocol(
                "SOCKS5 server selected unoffered no-auth method",
            )),
            0x02 => {
                // Username/password auth required
                if let (Some(user), Some(pass)) = (&self.username, &self.password) {
                    self.perform_auth(stream, user, pass)
                } else {
                    Err(Error::protocol(
                        "SOCKS5 server requires auth but no credentials provided",
                    ))
                }
            }
            0xFF => Err(Error::protocol("SOCKS5 no acceptable auth method")),
            _ => Err(Error::protocol(format!(
                "Unsupported SOCKS5 auth method: {}",
                response[1]
            ))),
        }
    }

    fn perform_auth<S: Read + Write>(
        &self,
        stream: &mut S,
        username: &str,
        password: &str,
    ) -> Result<()> {
        if !(1..=255).contains(&username.len()) || !(1..=255).contains(&password.len()) {
            return Err(Error::config(
                "SOCKS5 username/password must be 1..=255 bytes (RFC 1929)",
            ));
        }

        let mut auth = vec![0x01]; // Version
        auth.push(username.len() as u8);
        auth.extend_from_slice(username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());

        stream
            .write_all(&auth)
            .map_err(|e| Error::network(format!("Failed to send auth: {}", e)))?;

        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .map_err(|e| Error::network(format!("Failed to read auth response: {}", e)))?;

        if response[0] != 0x01 || response[1] != 0x00 {
            return Err(Error::protocol("SOCKS5 authentication failed"));
        }

        Ok(())
    }

    fn send_connect_request_target<S: Read + Write>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
    ) -> Result<()> {
        let mut request = vec![
            0x05, // Version
            0x01, // CONNECT command
            0x00, // Reserved
        ];

        match target {
            TargetAddr::Domain(domain, port) => {
                if domain.is_empty()
                    || domain.len() > u8::MAX as usize
                    || domain.bytes().any(|b| b <= b' ' || b == 0x7f)
                {
                    return Err(Error::config("Invalid SOCKS5 target domain"));
                }
                request.push(0x03); // Domain address type
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
                request.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    IpAddr::V4(ipv4) => {
                        request.push(0x01); // IPv4
                        request.extend_from_slice(&ipv4.octets());
                    }
                    IpAddr::V6(ipv6) => {
                        request.push(0x04); // IPv6
                        request.extend_from_slice(&ipv6.octets());
                    }
                }
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        stream
            .write_all(&request)
            .map_err(|e| Error::network(format!("Failed to send SOCKS5 CONNECT: {}", e)))?;

        Ok(())
    }

    fn read_connect_response<S: Read>(&self, stream: &mut S) -> Result<()> {
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 response: {}", e)))?;

        if header[0] != 0x05 {
            return Err(Error::protocol("Invalid SOCKS5 version in response"));
        }

        if header[2] != 0 {
            return Err(Error::protocol("Invalid SOCKS5 reserved byte"));
        }
        let status = header[1];
        if status != 0x00 {
            let error_msg = match status {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown error",
            };
            return Err(Error::network(format!(
                "SOCKS5 CONNECT failed: {}",
                error_msg
            )));
        }

        // Skip bound address in response
        match header[3] {
            0x01 => {
                // IPv4
                let mut addr_port = [0u8; 6];
                stream.read_exact(&mut addr_port)?;
            }
            0x04 => {
                // IPv6
                let mut addr_port = [0u8; 18];
                stream.read_exact(&mut addr_port)?;
            }
            0x03 => {
                // Domain
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf)?;
                let len = len_buf[0] as usize;
                if len == 0 {
                    return Err(Error::protocol("Empty SOCKS5 bound domain"));
                }
                let mut addr_port = vec![0u8; len + 2];
                stream.read_exact(&mut addr_port)?;
            }
            _ => {
                return Err(Error::protocol(
                    "Unsupported address type in SOCKS5 response",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn config() -> OutboundConfig {
        OutboundConfig {
            tag: "socks-test".into(),
            outbound_type: crate::engine::config::OutboundType::Socks5,
            server: Some("127.0.0.1".into()),
            port: Some(1080),
            options: Default::default(),
        }
    }
    struct Wire {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Wire {
        fn new(input: &[u8]) -> Self {
            Self {
                input: Cursor::new(input.to_vec()),
                output: Vec::new(),
            }
        }
    }
    impl Read for Wire {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Wire {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn refuses_authentication_downgrade_and_wrong_auth_version() {
        let mut cfg = config();
        cfg.options
            .insert("username".into(), nextjson::Value::String("u".into()));
        cfg.options
            .insert("password".into(), nextjson::Value::String("p".into()));
        let proxy = Socks5Outbound::new(cfg).unwrap();
        let mut downgrade = Wire::new(&[5, 0]);
        assert!(proxy.perform_handshake(&mut downgrade).is_err());
        assert_eq!(downgrade.output, [5, 1, 2]);
        let mut wrong_version = Wire::new(&[5, 2, 5, 0]);
        assert!(proxy.perform_handshake(&mut wrong_version).is_err());
        let mut valid = Wire::new(&[5, 2, 1, 0]);
        assert!(proxy.perform_handshake(&mut valid).is_ok());
    }

    #[test]
    fn rejects_incomplete_and_oversized_credentials_before_connect() {
        for (user, pass) in [
            (Some("u".to_string()), None),
            (None, Some("p".to_string())),
            (Some("".to_string()), Some("p".to_string())),
            (Some("u".repeat(256)), Some("p".to_string())),
        ] {
            let mut cfg = config();
            if let Some(user) = user {
                cfg.options
                    .insert("username".into(), nextjson::Value::String(user));
            }
            if let Some(pass) = pass {
                cfg.options
                    .insert("password".into(), nextjson::Value::String(pass));
            }
            assert!(Socks5Outbound::new(cfg).is_err());
        }
    }

    #[test]
    fn rejects_invalid_target_without_writing_a_truncated_length() {
        let proxy = Socks5Outbound::new(config()).unwrap();
        for domain in ["".to_string(), "a".repeat(256), "bad\nhost".to_string()] {
            let mut wire = Wire::new(&[]);
            assert!(
                proxy
                    .send_connect_request_target(&mut wire, &TargetAddr::Domain(domain, 443))
                    .is_err()
            );
            assert!(wire.output.is_empty());
        }
        let mut wire = Wire::new(&[]);
        assert!(
            proxy
                .send_connect_request_target(&mut wire, &TargetAddr::Domain("a".repeat(255), 443))
                .is_ok()
        );
        assert_eq!(wire.output[4], 255);
        assert_eq!(wire.output.len(), 262);
    }

    #[test]
    fn rejects_reserved_byte_and_empty_bound_domain() {
        let proxy = Socks5Outbound::new(config()).unwrap();
        for response in [&[5, 0, 1, 1][..], &[5, 0, 0, 3, 0][..], &[4, 0, 0, 1][..]] {
            assert!(
                proxy
                    .read_connect_response(&mut Cursor::new(response))
                    .is_err()
            );
        }
        assert!(
            proxy
                .read_connect_response(&mut Cursor::new([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]))
                .is_ok()
        );
    }
}
