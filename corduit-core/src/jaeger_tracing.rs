//! Tracing span helpers.
//!
//! Lightweight `tracing`-based instrumentation helpers. The former
//! OpenTelemetry / Jaeger OTLP export (the `jaeger` feature) was removed to
//! eliminate the `opentelemetry-*` / `tonic` / `reqwest` / `url` dependency
//! chain from the project — a necessary step toward a fully serde-free
//! dependency graph. Spans are still emitted through `tracing` and remain
//! consumable by the standard tracing subscribers in the logging layer.
//!
//! The public API surface (`TracingConfig`, `init_tracing`,
//! `shutdown_tracing`, the span helper types and the `trace_*!` macros) is
//! preserved for source compatibility.

use crate::error::Result;
use std::sync::Once;

static INIT: Once = Once::new();

/// Tracing configuration.
///
/// Retained for API compatibility. Without the OTLP exporter this only gates
/// the span helpers; the structured logger is configured separately in the
/// logging module.
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Whether tracing helpers are enabled.
    pub enabled: bool,
    /// Legacy Jaeger endpoint (kept for API compatibility; no OTLP export).
    pub jaeger_endpoint: Option<String>,
    /// Service name used in emitted spans.
    pub service_name: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jaeger_endpoint: None,
            service_name: "corduit".to_string(),
        }
    }
}

impl TracingConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_jaeger(mut self, endpoint: impl Into<String>) -> Self {
        self.enabled = true;
        self.jaeger_endpoint = Some(endpoint.into());
        self
    }

    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }
}

/// Initialize tracing. Without the OTLP exporter this is a no-op kept for
/// source compatibility; the structured logger is set up by the logging
/// module instead.
pub fn init_tracing(_config: TracingConfig) -> Result<()> {
    INIT.call_once(|| {});
    Ok(())
}

/// Shut tracing down. No-op without the OTLP exporter.
pub fn shutdown_tracing() {}

/// Instrument an async block with a `dns_resolution` span.
#[macro_export]
macro_rules! trace_dns_resolution {
    ($domain:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!("dns_resolution", domain = %$domain);
        async move { $body }.instrument(span).await
    }};
}

/// Instrument an async block with a `proxy_connection` span.
#[macro_export]
macro_rules! trace_proxy_connection {
    ($target:expr, $protocol:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!("proxy_connection", target = %$target, protocol = %$protocol);
        async move { $body }.instrument(span).await
    }};
}

/// Record a routing decision in a `routing_decision` span.
#[macro_export]
macro_rules! trace_routing_decision {
    ($domain:expr, $ip:expr, $rule:expr, $outbound:expr) => {{
        tracing::info_span!("routing_decision", domain = ?$domain, ip = ?$ip)
            .in_scope(|| {
                tracing::info!(
                    "Routing decision: domain={:?}, ip={:?}, rule={}, outbound={}",
                    $domain,
                    $ip,
                    $rule,
                    $outbound
                );
            });
    }};
}

/// Instrument an async block with an `inbound_connection` span.
#[macro_export]
macro_rules! trace_inbound_connection {
    ($inbound_type:expr, $src_addr:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!(
            "inbound_connection",
            inbound_type = %$inbound_type,
            src_addr = %$src_addr
        );
        async move { $body }.instrument(span).await
    }};
}

/// Instrument an async block with an `outbound_connection` span.
#[macro_export]
macro_rules! trace_outbound_connection {
    ($outbound_type:expr, $target:expr, $body:expr) => {{
        use tracing::Instrument;
        let span = tracing::info_span!(
            "outbound_connection",
            outbound_type = %$outbound_type,
            target = %$target
        );
        async move { $body }.instrument(span).await
    }};
}

/// A `dns_resolution` span that stays entered until dropped.
pub struct DnsResolutionSpan {
    _span: tracing::span::EnteredSpan,
}

impl DnsResolutionSpan {
    pub fn new(domain: &str) -> Self {
        let span = tracing::info_span!("dns_resolution", domain = %domain);
        Self {
            _span: span.entered(),
        }
    }

    pub fn record_result(&self, success: bool, ip_count: usize) {
        tracing::Span::current().record("success", success);
        tracing::Span::current().record("ip_count", ip_count as u64);
    }
}

/// A `proxy_connection` span that stays entered until dropped.
pub struct ProxyConnectionSpan {
    _span: tracing::span::EnteredSpan,
}

impl ProxyConnectionSpan {
    pub fn new(target: &str, protocol: &str) -> Self {
        let span = tracing::info_span!("proxy_connection", target = %target, protocol = %protocol);
        Self {
            _span: span.entered(),
        }
    }

    pub fn record_success(&self, bytes_sent: u64, bytes_received: u64) {
        tracing::Span::current().record("success", true);
        tracing::Span::current().record("bytes_sent", bytes_sent);
        tracing::Span::current().record("bytes_received", bytes_received);
    }

    pub fn record_error(&self, error: &str) {
        tracing::Span::current().record("success", false);
        tracing::Span::current().record("error", error);
    }
}

/// A `routing_decision` span that stays entered until dropped.
pub struct RoutingDecisionSpan {
    _span: tracing::span::EnteredSpan,
}

impl RoutingDecisionSpan {
    pub fn new(domain: Option<&str>, ip: Option<&str>) -> Self {
        let span = tracing::info_span!("routing_decision", domain = ?domain, ip = ?ip);
        Self {
            _span: span.entered(),
        }
    }

    pub fn record_match(&self, rule_type: &str, rule_payload: &str, outbound: &str) {
        tracing::info!(
            rule_type = %rule_type,
            rule_payload = %rule_payload,
            outbound = %outbound,
            "Routing rule matched"
        );
    }
}

/// An `inbound_connection` span that stays entered until dropped.
pub struct InboundConnectionSpan {
    _span: tracing::span::EnteredSpan,
}

impl InboundConnectionSpan {
    pub fn new(inbound_type: &str, src_addr: &str) -> Self {
        let span = tracing::info_span!(
            "inbound_connection",
            inbound_type = %inbound_type,
            src_addr = %src_addr
        );
        Self {
            _span: span.entered(),
        }
    }

    pub fn record_target(&self, target: &str) {
        tracing::Span::current().record("target", target);
    }
}

/// An `outbound_connection` span that stays entered until dropped.
pub struct OutboundConnectionSpan {
    _span: tracing::span::EnteredSpan,
}

impl OutboundConnectionSpan {
    pub fn new(outbound_type: &str, target: &str) -> Self {
        let span = tracing::info_span!(
            "outbound_connection",
            outbound_type = %outbound_type,
            target = %target
        );
        Self {
            _span: span.entered(),
        }
    }

    pub fn record_latency(&self, latency_ms: u64) {
        tracing::Span::current().record("latency_ms", latency_ms);
    }

    pub fn record_error(&self, error: &str) {
        tracing::Span::current().record("error", error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();
        assert!(!config.enabled);
        assert!(config.jaeger_endpoint.is_none());
        assert_eq!(config.service_name, "corduit");
    }

    #[test]
    fn test_tracing_config_with_jaeger() {
        let config = TracingConfig::new()
            .with_jaeger("http://localhost:4317")
            .with_service_name("test-service");

        assert!(config.enabled);
        assert_eq!(
            config.jaeger_endpoint,
            Some("http://localhost:4317".to_string())
        );
        assert_eq!(config.service_name, "test-service");
    }

    #[test]
    fn test_span_creation() {
        let _dns_span = DnsResolutionSpan::new("example.com");
        let _proxy_span = ProxyConnectionSpan::new("example.com:443", "https");
        let _routing_span = RoutingDecisionSpan::new(Some("example.com"), None);
    }

    #[test]
    fn test_init_tracing_is_noop() {
        assert!(init_tracing(TracingConfig::default()).is_ok());
        shutdown_tracing();
    }
}
