//! SIP003 plugins: the transport a Shadowsocks node's `plugin` names.
//!
//! `plugin` + `plugin-opts` is how Clash-family subscriptions spell
//! "shadowsocks behind something else". Every plugin here shapes the **TCP**
//! stream the SS records travel inside; once the socket is wrapped the node is
//! an ordinary Shadowsocks outbound, which is why the wiring lives in one place:
//!
//! ```text
//! client target ──► SS AEAD frames ──► [plugin shaping] ──► server:port
//! ```
//!
//! * **`obfs`** (`simple-obfs`): `mode: http` writes the fabricated `curl`
//!   request and then raw SS bytes; `mode: tls` writes a fabricated
//!   `ClientHello` whose session ticket carries the first record, then wraps
//!   every write in `17 03 03` application-data records. Both shapes come from
//!   [`crate::protocol::obfs`], which Snell's obfs uses too — same wire,
//!   different fabricated request.
//! * **`v2ray-plugin`** in `websocket` mode is a WebSocket (optionally over
//!   TLS) whose binary messages carry the SS records, with the `Host` header
//!   from `plugin-opts.host`. `mux` is deliberately not implemented as a
//!   setting: it is a client-side stream multiplexing *optimisation* of an
//!   otherwise identical protocol, so connections work without it.
//! * **`shadow-tls`** runs the ShadowTLS v3 handshake — the same client as
//!   [`crate::engine::outbound::shadowtls`], which serves the standalone
//!   `shadowtls` outbound — and then carries SS records inside its frames.
//!
//! None of the three carries UDP: simple-obfs is TCP-only by construction, and
//! v2ray-plugin's and shadow-tls's UDP forms are different wires (QUIC
//! datagrams / a UDP framing the server expects separately). The outbound
//! therefore disables UDP whenever a plugin is present rather than sending
//! datagrams the server will not answer.
//!
//! A plugin name this build does not implement is **refused by name**: dialling
//! the node as plain Shadowsocks would connect and then fail every request,
//! which is worse than a config error that says which plugin is missing.

use crate::common::stream::BoxStream;
use crate::engine::error::{Error, Result};
use crate::engine::tls::yaml_value_to_string;
use crate::protocol::obfs::{HttpObfsStream, TlsObfsStream};
use nextjson::Value;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};

/// The `obfs-host` simple-obfs's TLS mode falls back to when the profile names
/// none. Its TLS mode only fabricates a `ClientHello`, so any plausible name
/// works; this is the upstream default.
pub(crate) const DEFAULT_SIMPLE_OBFS_TLS_HOST: &str = "www.bing.com";

/// The `obfs-host` simple-obfs's HTTP mode falls back to.
const DEFAULT_SIMPLE_OBFS_HTTP_HOST: &str = "bing.com";

/// One resolved plugin command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plugin {
    /// No plugin: the socket carries raw Shadowsocks.
    None,
    /// simple-obfs in HTTP mode.
    ObfsHttp {
        host: String,
        uri: String,
        method: String,
    },
    /// simple-obfs in TLS mode.
    ObfsTls { host: String },
    /// `v2ray-plugin` in WebSocket mode.
    V2rayWs {
        tls: bool,
        /// The `Host` header (defaults to the server name).
        host: String,
        path: String,
        /// The TLS server name the handshake presents.
        sni: String,
    },
    /// ShadowTLS v3 under a Shadowsocks node.
    #[cfg(feature = "shadowtls")]
    ShadowTls { host: String, password: String },
}

impl Plugin {
    /// Resolve `plugin` + `plugin-opts` from an outbound's option map.
    ///
    /// `server` supplies the defaults that depend on the node (a v2ray-plugin
    /// WebSocket without an explicit `host` uses it for both the `Host` header
    /// and the TLS name).
    pub(crate) fn parse(options: &HashMap<String, Value>, server: &str) -> Result<Self> {
        let name = options
            .get("plugin")
            .map(yaml_value_to_string)
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let opts = options.get("plugin-opts");
        if name.is_empty() {
            if opts.is_some() {
                warn!(
                    "`plugin-opts` is set without a `plugin`; the options are ignored and the \
                     node is dialled as plain Shadowsocks"
                );
            }
            return Ok(Plugin::None);
        }

        let opt = |key: &str| -> Option<String> {
            opts.and_then(|value| value.get(key))
                .map(yaml_value_to_string)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        match name.as_str() {
            "obfs" | "simple-obfs" | "obfs-local" => {
                let mode = opt("mode")
                    .unwrap_or_else(|| "http".to_string())
                    .to_ascii_lowercase();
                match mode.as_str() {
                    "http" => {
                        let host = opt("host")
                            .unwrap_or_else(|| DEFAULT_SIMPLE_OBFS_HTTP_HOST.to_string());
                        let uri = opt("uri")
                            .or_else(|| opt("path"))
                            .unwrap_or_else(|| "/".into());
                        let method = opt("method").unwrap_or_else(|| "GET".to_string());
                        crate::protocol::obfs::validate_obfs_host(&host)
                            .and_then(|()| crate::protocol::obfs::validate_obfs_uri(&uri))
                            .and_then(|()| crate::protocol::obfs::validate_obfs_method(&method))
                            .map_err(|e| Error::config(format!("simple-obfs: {e}")))?;
                        Ok(Plugin::ObfsHttp { host, uri, method })
                    }
                    "tls" => {
                        let host =
                            opt("host").unwrap_or_else(|| DEFAULT_SIMPLE_OBFS_TLS_HOST.to_string());
                        crate::protocol::obfs::validate_obfs_host(&host)
                            .map_err(|e| Error::config(format!("simple-obfs: {e}")))?;
                        Ok(Plugin::ObfsTls { host })
                    }
                    other => Err(Error::config(format!(
                        "simple-obfs mode `{other}` is not implemented; `http` and `tls` are"
                    ))),
                }
            }
            "v2ray-plugin" => {
                let mode = opt("mode")
                    .unwrap_or_else(|| "websocket".to_string())
                    .to_ascii_lowercase();
                if mode != "websocket" {
                    return Err(Error::config(format!(
                        "v2ray-plugin mode `{mode}` is not implemented; only `websocket` is \
                         (its `quic` mode is a different wire, and `mux` is a client-side \
                         optimisation that is not required to talk to the server)"
                    )));
                }
                let tls = opts
                    .and_then(|value| value.get("tls"))
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false);
                let host = opt("host")
                    .map(|host| host.split(':').next().unwrap_or(&host).to_string())
                    .unwrap_or_else(|| server.to_string());
                let path = opt("path").unwrap_or_else(|| "/".to_string());
                // The WebSocket handshake writes this value into its request
                // line; the same rule as every other fabricated head applies.
                if !path.starts_with('/') || crate::common::text::has_line_breaking_byte(&path) {
                    return Err(Error::config(format!(
                        "v2ray-plugin path must start with '/' and hold no control byte: {path:?}"
                    )));
                }
                let sni = opt("sni").unwrap_or_else(|| host.clone());
                Ok(Plugin::V2rayWs {
                    tls,
                    host,
                    path,
                    sni,
                })
            }
            "shadow-tls" => {
                #[cfg(not(feature = "shadowtls"))]
                {
                    return Err(Error::config(
                        "the `shadow-tls` plugin needs the `shadowtls` build feature, which \
                         this build does not carry",
                    ));
                }
                #[cfg(feature = "shadowtls")]
                {
                    let host = opt("host").ok_or_else(|| {
                        Error::config(
                            "shadow-tls requires `plugin-opts.host`: the handshake impersonates a \
                             real TLS session, so it has to name the site the server proxies to",
                        )
                    })?;
                    let password = opt("password").ok_or_else(|| {
                        Error::config("shadow-tls requires `plugin-opts.password`")
                    })?;
                    crate::protocol::obfs::validate_obfs_host(&host)
                        .map_err(|e| Error::config(format!("shadow-tls: {e}")))?;
                    let version = opt("version").unwrap_or_else(|| "3".to_string());
                    if version.trim() != "3" {
                        return Err(Error::config(format!(
                            "shadow-tls version {version} is not implemented: v1 and v2 sign the \
                             handshake differently, so speaking v3's rules to them fails like a \
                             wrong password. Version 3 only."
                        )));
                    }
                    Ok(Plugin::ShadowTls { host, password })
                }
            }
            other => Err(Error::config(format!(
                "the Shadowsocks plugin `{other}` is not implemented; this build implements \
                 `obfs` (simple-obfs), `v2ray-plugin` (websocket) and `shadow-tls` (v3)"
            ))),
        }
    }

    /// Whether the plugin can carry UDP datagrams. Only "no plugin" can.
    pub(crate) fn carries_udp(&self) -> bool {
        matches!(self, Plugin::None)
    }

    /// Dial `server:port` and apply the plugin's shaping.
    ///
    /// The dial happens here rather than in the caller because ShadowTLS has to
    /// own the socket from its first byte — its handshake *is* the first bytes
    /// — and a plugin interface that sometimes takes a connected socket and
    /// sometimes opens its own would be two interfaces.
    pub(crate) fn wrap(&self, server: &str, port: u16, timeout: Duration) -> Result<BoxStream> {
        match self {
            Plugin::None => Ok(Box::new(dial(server, port, timeout)?)),
            Plugin::ObfsHttp { host, uri, method } => Ok(Box::new(
                HttpObfsStream::simple_obfs(
                    Box::new(dial(server, port, timeout)?),
                    host.clone(),
                    uri.clone(),
                    port,
                    method.clone(),
                )
                .map_err(|e| Error::config(format!("simple-obfs: {e}")))?,
            )),
            Plugin::ObfsTls { host } => Ok(Box::new(
                TlsObfsStream::new(Box::new(dial(server, port, timeout)?), host.clone())
                    .map_err(|e| Error::config(format!("simple-obfs: {e}")))?,
            )),
            Plugin::V2rayWs {
                tls,
                host,
                path,
                sni,
            } => {
                let tcp = dial(server, port, timeout)?;
                let stream: BoxStream = if *tls {
                    let connector =
                        crate::engine::tls::TlsConnector::new(crate::engine::tls::ClientConfig {
                            server_name: Some(sni.clone()),
                            alpn: vec!["http/1.1".to_string()],
                            skip_cert_verify: false,
                            enable_sni: true,
                        })
                        .map_err(|e| Error::Tls {
                            message: format!("v2ray-plugin TLS: {e}"),
                            source: None,
                        })?;
                    connector.connect(tcp, sni).map_err(|e| Error::Tls {
                        message: format!("v2ray-plugin TLS handshake failed: {e}"),
                        source: None,
                    })?
                } else {
                    Box::new(tcp)
                };
                let ws =
                    crate::protocol::ws::WebSocket::connect(stream, host, path, &HashMap::new())
                        .map_err(|e| {
                            Error::network(format!("v2ray-plugin WebSocket handshake failed: {e}"))
                        })?;
                debug!("v2ray-plugin: websocket transport up (tls={tls})");
                Ok(Box::new(ws))
            }
            #[cfg(feature = "shadowtls")]
            Plugin::ShadowTls { host, password } => {
                super::shadowtls::open_client_stream(server, port, password, host, timeout)
            }
        }
    }
}

/// A connected, timeout-armed socket for the non-ShadowTLS paths.
fn dial(server: &str, port: u16, timeout: Duration) -> Result<std::net::TcpStream> {
    let tcp = crate::common::socket::connect_host(server, port, timeout).map_err(|e| {
        Error::network(format!(
            "Failed to connect to the Shadowsocks server {server}:{port} for its plugin: {e}"
        ))
    })?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| Error::network(format!("set read timeout: {e}")))?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| Error::network(format!("set write timeout: {e}")))?;
    tcp.set_nodelay(true).ok();
    Ok(tcp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextjson::Value;

    fn options(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    fn string(value: &str) -> Value {
        Value::String(value.to_string())
    }

    fn object(pairs: &[(&str, Value)]) -> Value {
        Value::Object(options(pairs).into_iter().collect())
    }

    #[test]
    fn a_node_without_a_plugin_is_plain_shadowsocks() {
        assert_eq!(
            Plugin::parse(&HashMap::new(), "example.com").unwrap(),
            Plugin::None
        );
        // Options without a plugin are ignored rather than half-applied.
        let opts = options(&[("plugin-opts", object(&[("mode", string("tls"))]))]);
        assert_eq!(Plugin::parse(&opts, "example.com").unwrap(), Plugin::None);
        assert!(Plugin::None.carries_udp());
    }

    #[test]
    fn simple_obfs_modes_resolve_with_their_defaults() {
        let plain = options(&[("plugin", string("obfs"))]);
        assert_eq!(
            Plugin::parse(&plain, "example.com").unwrap(),
            Plugin::ObfsHttp {
                host: DEFAULT_SIMPLE_OBFS_HTTP_HOST.to_string(),
                uri: "/".to_string(),
                method: "GET".to_string(),
            }
        );

        let tls = options(&[
            ("plugin", string("simple-obfs")),
            ("plugin-opts", object(&[("mode", string("tls"))])),
        ]);
        assert_eq!(
            Plugin::parse(&tls, "example.com").unwrap(),
            Plugin::ObfsTls {
                host: DEFAULT_SIMPLE_OBFS_TLS_HOST.to_string(),
            }
        );

        let detailed = options(&[
            ("plugin", string("obfs-local")),
            (
                "plugin-opts",
                object(&[
                    ("mode", string("HTTP")),
                    ("host", string("cdn.example")),
                    ("uri", string("/ws")),
                    ("method", string("POST")),
                ]),
            ),
        ]);
        assert_eq!(
            Plugin::parse(&detailed, "example.com").unwrap(),
            Plugin::ObfsHttp {
                host: "cdn.example".to_string(),
                uri: "/ws".to_string(),
                method: "POST".to_string(),
            }
        );

        let bad = options(&[
            ("plugin", string("obfs")),
            ("plugin-opts", object(&[("mode", string("quic"))])),
        ]);
        let err = Plugin::parse(&bad, "example.com").unwrap_err().to_string();
        assert!(err.contains("simple-obfs mode"), "{err}");
    }

    /// A relative URI, a method or host holding CR/LF, and an over-long host
    /// are refused by name at build time: the fabricated head is assembled by
    /// text substitution, and a silent fallback would hide a profile that
    /// cannot work (or, worse, write the injected headers).
    #[test]
    fn plugin_values_that_cannot_sit_in_the_head_are_refused() {
        let cases: &[(&str, Value)] = &[
            ("uri", string("ws")),
            ("uri", string("/a\r\nHost: evil")),
            ("method", string("GET\r\nHost: evil")),
            ("host", string("a b")),
            ("host", string("a\x00b")),
        ];
        for (key, value) in cases {
            let opts = options(&[
                ("plugin", string("obfs")),
                ("plugin-opts", object(&[(key, value.clone())])),
            ]);
            let err = Plugin::parse(&opts, "example.com").unwrap_err().to_string();
            assert!(err.contains("simple-obfs"), "{key}: {err}");
        }

        let too_long = options(&[
            ("plugin", string("obfs")),
            (
                "plugin-opts",
                object(&[("mode", string("tls")), ("host", string(&"a".repeat(300)))]),
            ),
        ]);
        assert!(Plugin::parse(&too_long, "example.com").is_err());
    }

    #[test]
    fn v2ray_plugin_defaults_to_the_node_and_wants_websocket() {
        let plain = options(&[("plugin", string("v2ray-plugin"))]);
        assert_eq!(
            Plugin::parse(&plain, "node.example").unwrap(),
            Plugin::V2rayWs {
                tls: false,
                host: "node.example".to_string(),
                path: "/".to_string(),
                sni: "node.example".to_string(),
            }
        );

        let detailed = options(&[
            ("plugin", string("v2ray-plugin")),
            (
                "plugin-opts",
                object(&[
                    ("mode", string("websocket")),
                    ("tls", Value::Bool(true)),
                    ("host", string("front.example:443")),
                    ("path", string("/ray")),
                ]),
            ),
        ]);
        assert_eq!(
            Plugin::parse(&detailed, "node.example").unwrap(),
            Plugin::V2rayWs {
                tls: true,
                host: "front.example".to_string(),
                path: "/ray".to_string(),
                sni: "front.example".to_string(),
            }
        );

        let bad = options(&[
            ("plugin", string("v2ray-plugin")),
            ("plugin-opts", object(&[("mode", string("quic"))])),
        ]);
        let err = Plugin::parse(&bad, "node.example").unwrap_err().to_string();
        assert!(err.contains("v2ray-plugin mode"), "{err}");

        let relative = options(&[
            ("plugin", string("v2ray-plugin")),
            ("plugin-opts", object(&[("path", string("ray"))])),
        ]);
        let err = Plugin::parse(&relative, "node.example")
            .unwrap_err()
            .to_string();
        assert!(err.contains("path must start"), "{err}");

        let injected = options(&[
            ("plugin", string("v2ray-plugin")),
            (
                "plugin-opts",
                object(&[("path", string("/ray\r\nX-Injected: 1"))]),
            ),
        ]);
        assert!(Plugin::parse(&injected, "node.example").is_err());
    }

    #[cfg(feature = "shadowtls")]
    #[test]
    fn shadow_tls_requires_its_host_password_and_version_three() {
        let ok = options(&[
            ("plugin", string("shadow-tls")),
            (
                "plugin-opts",
                object(&[
                    ("host", string("www.bing.com")),
                    ("password", string("s3cret")),
                    ("version", string("3")),
                ]),
            ),
        ]);
        assert_eq!(
            Plugin::parse(&ok, "node.example").unwrap(),
            Plugin::ShadowTls {
                host: "www.bing.com".to_string(),
                password: "s3cret".to_string(),
            }
        );

        let missing = options(&[("plugin", string("shadow-tls"))]);
        assert!(Plugin::parse(&missing, "node.example").is_err());

        let v2 = options(&[
            ("plugin", string("shadow-tls")),
            (
                "plugin-opts",
                object(&[
                    ("host", string("a.example")),
                    ("password", string("x")),
                    ("version", string("2")),
                ]),
            ),
        ]);
        let err = Plugin::parse(&v2, "node.example").unwrap_err().to_string();
        assert!(
            err.contains("version 3 only") || err.contains("Version 3 only"),
            "{err}"
        );
    }

    #[test]
    fn an_unknown_plugin_is_refused_by_name() {
        let unknown = options(&[("plugin", string("kcptun"))]);
        let err = Plugin::parse(&unknown, "example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("kcptun"), "{err}");
        assert!(err.contains("not implemented"), "{err}");
    }
}
