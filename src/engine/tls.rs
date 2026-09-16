use crate::engine::error::{Error, Result};

pub use crate::protocol::tls::{ClientConfig, TlsConnector};

/// The default ALPN offer by transport shape.
///
/// A WebSocket upgrade is HTTP/1.1 by definition: offering `h2` lets the
/// peer negotiate HTTP/2 and then every HTTP/1.1 upgrade byte is an HTTP/2
/// protocol error (a reference Xray server answers with an h2 SETTINGS
/// frame and closes the connection). Raw TLS transports keep the
/// browser-shaped `h2` + `http/1.1` offer, matching v2ray/Xray clients.
pub fn default_alpn(websocket: bool) -> Vec<String> {
    if websocket {
        vec!["http/1.1".to_string()]
    } else {
        vec!["h2".to_string(), "http/1.1".to_string()]
    }
}

/// Resolve the ALPN offer: an explicit list wins, otherwise the default
/// for the transport shape applies.
pub fn effective_alpn(explicit: &[String], websocket: bool) -> Vec<String> {
    if explicit.is_empty() {
        default_alpn(websocket)
    } else {
        explicit.to_vec()
    }
}

pub fn yaml_value_to_string(value: &nextjson::Value) -> String {
    match value {
        nextjson::Value::String(s) => s.clone(),
        nextjson::Value::Number(n) => n.to_string(),
        nextjson::Value::Bool(b) => b.to_string(),
        _ => value.as_str().map(|s| s.to_string()).unwrap_or_default(),
    }
}

#[derive(Default, Clone)]
pub struct AdvancedTlsOptions {
    #[cfg(feature = "tls13")]
    pub fingerprint: Option<String>,
    #[cfg(feature = "reality")]
    pub reality: Option<crate::protocol::reality::RealityClientOptions>,
}

impl AdvancedTlsOptions {
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "tls13")]
        if self
            .fingerprint
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
        {
            return false;
        }
        #[cfg(feature = "reality")]
        if self.reality.is_some() {
            return false;
        }
        true
    }

    pub fn from_options(
        options: &std::collections::HashMap<String, nextjson::Value>,
        #[cfg_attr(not(feature = "reality"), allow(unused_variables))] default_server_name: &str,
    ) -> Result<Self> {
        #[cfg_attr(not(any(feature = "tls13", feature = "reality")), allow(unused_mut))]
        let mut out = AdvancedTlsOptions::default();

        let security = options
            .get("security")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let fingerprint = options
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if security == "reality" {
            #[cfg(feature = "reality")]
            {
                let reality = crate::protocol::reality::RealityClientOptions::from_options(
                    options,
                    default_server_name,
                )
                .map_err(|e| Error::config(format!("REALITY outbound options: {e}")))?;
                out.fingerprint = Some(
                    fingerprint
                        .clone()
                        .unwrap_or_else(|| reality.fingerprint.canonical_name().to_string()),
                );
                out.reality = Some(reality);
                return Ok(out);
            }
            #[cfg(not(feature = "reality"))]
            return Err(Error::config(
                "this outbound uses security 'reality', but the build has the `reality` feature \
                 disabled; rebuild with --features reality",
            ));
        }

        if let Some(name) = fingerprint {
            #[cfg(feature = "tls13")]
            {
                crate::protocol::tls13::fingerprint::Fingerprint::parse(&name)
                    .map_err(|e| Error::config(format!("outbound fingerprint: {e}")))?;
                out.fingerprint = Some(name);
                return Ok(out);
            }
            #[cfg(not(feature = "tls13"))]
            return Err(Error::config(format!(
                "this outbound sets fingerprint '{name}', but the build has the `tls13` feature \
                 disabled; rebuild with --features tls13"
            )));
        }

        Ok(out)
    }
}

#[cfg(feature = "tls13")]
const ADVANCED_RELAY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1000);

pub fn connect_advanced_tls(
    stream: std::net::TcpStream,
    server_name: &str,
    alpn: &[String],
    skip_cert_verify: bool,
    options: &AdvancedTlsOptions,
) -> Result<crate::common::stream::BoxStream> {
    #[cfg(feature = "reality")]
    if let Some(reality) = options.reality.clone() {
        let alpn = effective_alpn(alpn, false);
        return crate::protocol::reality::connect(stream, reality, alpn).map_err(|e| Error::Tls {
            message: format!("REALITY handshake failed: {e}"),
            source: None,
        });
    }

    #[cfg(feature = "tls13")]
    if let Some(name) = options.fingerprint.as_deref() {
        use crate::protocol::tls13::fingerprint::Fingerprint;
        let fingerprint = Fingerprint::parse(name).map_err(|e| Error::Tls {
            message: e.to_string(),
            source: None,
        })?;
        let alpn = effective_alpn(alpn, false);
        let socket = crate::common::shared_socket::SharedTcpStream::new(stream);
        let reader = socket.clone();
        let writer = socket.clone();
        let control = socket.clone();
        let hook_socket = socket.clone();
        let shutdown_hook =
            Some(
                std::sync::Arc::new(move |how: std::net::Shutdown| hook_socket.shutdown(how))
                    as std::sync::Arc<
                        dyn Fn(std::net::Shutdown) -> std::io::Result<()> + Send + Sync,
                    >,
            );
        let config = crate::protocol::tls13::Tls13ClientConfig {
            server_name: server_name.to_string(),
            alpn,
            fingerprint: fingerprint.clone(),
            now: unix_now_seconds(),
            roots: if skip_cert_verify {
                None
            } else {
                Some(crate::common::roots::system_root_store().clone())
            },
            verify: !skip_cert_verify,
            auth: None,
            hello_hook: None,
            compatibility_ccs: !matches!(fingerprint, Fingerprint::Off),
            shutdown_hook,
        };
        let tls =
            crate::protocol::tls13::connect(reader, writer, config).map_err(|e| Error::Tls {
                message: format!("TLS 1.3 handshake failed: {e}"),
                source: None,
            })?;
        let _ = control.set_read_timeout(Some(ADVANCED_RELAY_READ_TIMEOUT));
        return Ok(Box::new(tls) as crate::common::stream::BoxStream);
    }

    let _ = (stream, server_name, alpn, skip_cert_verify, options);
    Err(Error::config(
        "connect_advanced_tls called without any advanced TLS option",
    ))
}

#[cfg(feature = "tls13")]
fn unix_now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_offers_http11_only() {
        assert_eq!(default_alpn(true), vec!["http/1.1".to_string()]);
    }

    #[test]
    fn raw_tls_keeps_the_browser_default() {
        assert_eq!(
            default_alpn(false),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }

    #[test]
    fn explicit_alpn_wins_over_any_default() {
        let explicit = vec!["custom/1".to_string()];
        assert_eq!(effective_alpn(&explicit, false), explicit);
        assert_eq!(effective_alpn(&explicit, true), explicit.clone());
    }

    #[test]
    fn empty_alpn_falls_back_to_the_transport_default() {
        assert_eq!(effective_alpn(&[], true), vec!["http/1.1".to_string()]);
        assert_eq!(
            effective_alpn(&[], false),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }
}
