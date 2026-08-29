//! QUIC client configuration.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::obfs::Salamander;

/// Congestion-control algorithm selection.
///
/// The transport currently implements a NewReno-style AIMD controller
/// (RFC 5681 semantics adapted to QUIC's byte-based windows). The variants
/// are kept so configuration written for quinn keeps parsing; all of them
/// currently drive the same controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl CongestionControl {
    /// Parse from the spellings used by TUIC / Hysteria2 configs.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "cubic" => Some(Self::Cubic),
            "new-reno" | "newreno" => Some(Self::NewReno),
            "bbr" => Some(Self::Bbr),
            _ => None,
        }
    }
}

impl std::str::FromStr for CongestionControl {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s).ok_or(())
    }
}

/// Configuration for a QUIC v1 client connection.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Remote address.
    pub server_addr: SocketAddr,
    /// SNI / hostname used for certificate verification and the TLS
    /// `server_name` extension.
    pub server_name: String,
    /// ALPN protocols to offer (e.g. `["h3"]`).
    pub alpn: Vec<String>,
    /// Skip certificate chain / hostname verification (discouraged).
    pub skip_cert_verify: bool,
    /// Local bind address (`None` = ephemeral).
    pub local_addr: Option<SocketAddr>,
    /// Idle timeout; the connection closes after this long without a
    /// received packet.
    pub idle_timeout: Duration,
    /// Keep-alive ping interval (disables the idle timeout effectively).
    pub keep_alive_interval: Option<Duration>,
    /// Handshake timeout.
    pub handshake_timeout: Duration,
    /// Initial `max_streams_bidi` we advertise (per-direction limit on
    /// peer-initiated streams; a client rarely needs many inbound).
    pub max_concurrent_bidi_streams: u64,
    /// Initial `max_streams_uni` we advertise.
    pub max_concurrent_uni_streams: u64,
    /// Initial `max_data` we advertise (total receive window).
    pub initial_max_data: u64,
    /// Initial `max_stream_data_bidi_local` / `..._remote` / `..._uni`
    /// windows we advertise for receive.
    pub initial_max_stream_data: u64,
    /// Maximum UDP payload size we accept (`max_udp_payload_size` TP).
    pub max_udp_payload_size: u64,
    /// Congestion-control selection.
    pub congestion_control: CongestionControl,
    /// Optional "Salamander" packet obfuscation (Hysteria 2). When set,
    /// every datagram is wrapped as `[8-byte salt][XOR(keystream)]` before
    /// hitting the wire and unwrapped on receive.
    pub obfs: Option<Arc<Salamander>>,
}

impl ClientConfig {
    /// Sensible defaults for a proxy outbound.
    pub fn new(server_addr: SocketAddr, server_name: String) -> Self {
        Self {
            server_addr,
            server_name,
            alpn: vec!["h3".to_string()],
            skip_cert_verify: false,
            local_addr: None,
            idle_timeout: Duration::from_secs(30),
            keep_alive_interval: None,
            handshake_timeout: Duration::from_secs(15),
            max_concurrent_bidi_streams: 64,
            max_concurrent_uni_streams: 64,
            initial_max_data: 16 * 1024 * 1024,
            initial_max_stream_data: 1024 * 1024,
            max_udp_payload_size: 1200,
            congestion_control: CongestionControl::default(),
            obfs: None,
        }
    }
}
