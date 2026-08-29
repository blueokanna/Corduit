//! Certificate-verification marker kept for API compatibility.
//!
//! The old `SkipServerVerification` implemented rustls'
//! `ServerCertVerifier` to accept any server certificate. With the move to
//! courierust's self-contained TLS stack, skipping verification is expressed
//! as a configuration flag ([`ClientConfig::skip_cert_verify`]) instead of a
//! custom verifier object. This marker type remains so code that named the
//! type (re-exports, stored fields) keeps compiling; it has no behavior.

/// Marker for "accept any server certificate", kept for API compatibility.
///
/// Prefer [`ClientConfig::skip_cert_verify`] on new code.
#[derive(Debug, Clone, Copy, Default)]
pub struct SkipServerVerification;
