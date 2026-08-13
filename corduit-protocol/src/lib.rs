//! # Corduit Protocol
//!
//! Native, in-repo implementations of the wire protocols and transports used by
//! the Corduit engine — no third-party protocol forks, one version, tested
//! together with the rest of the workspace.
//!
//! ## Modules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`address`] | SOCKS-style address encoding/decoding (`Address`, `AddressType`) |
//! | [`transport`] | Layered transports: TLS, h2, gRPC, WebSocket |
//! | [`quic`] | QUIC (quinn-based) client/server/crypto/session helpers |
//! | [`tls`] | TLS client/server/verifier layers over rustls |
//! | [`wireguard`] | WireGuard handshake & data-path primitives (curve25519, ChaCha20Poly1305) |
//! | [`tuic`] | TUIC v5 protocol |
//! | [`tuic_quinn`] | TUIC over QUIC |
//!
//! Feature-gated modules are marked with the corresponding crate feature
//! (`quic`, `tls`, `wireguard`, `tuic`, `tuic-quinn`).
//!
//! ## Quick start
//!
//! ```rust
//! use corduit_protocol::address::{Address, AddressType};
//!
//! let addr = Address::from_domain("example.com", 443);
//! assert_eq!(addr.address_type(), AddressType::Domain);
//!
//! let mut buf = Vec::new();
//! addr.write_to_vec(&mut buf);
//! let (decoded, _consumed) = Address::read_from(&buf).expect("valid address");
//! assert_eq!(addr, decoded);
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]

/// String-based codec for unit-variant enums whose JSON form is a plain string
/// (e.g. `"mode": "gun"`), matching the serde-era config spelling.
///
/// nextjson's derived enum codec is externally tagged (`{"gun": null}`);
/// protocol configs spell these values as strings, so the enums below get an
/// explicit string codec instead of the derive.
#[macro_export]
macro_rules! impl_protocol_enum {
    ($ty:ident { $($variant:ident => $canonical:literal $(| $alias:literal)*),+ $(,)? }) => {
        impl ::nextjson::NsonSchema for $ty {
            const SCHEMA: ::nextjson::TypeSchema = ::nextjson::TypeSchema::Str;
        }
        impl ::nextjson::NsonSerialize for $ty {
            fn nextencode<E: ::nextjson::FormatEncoder>(
                &self,
                e: &mut E,
            ) -> ::core::result::Result<(), E::Error> {
                let name = match self {
                    $($ty::$variant => $canonical,)+
                };
                e.write_str(name)
            }
        }
        impl<'de> ::nextjson::NsonDeserialize<'de> for $ty {
            fn nextdecode_into<D: ::nextjson::FormatDecoder<'de>>(
                d: &mut D,
                out: &mut ::nextjson::DecodeSlot<Self>,
            ) -> ::core::result::Result<(), D::Error> {
                let s = d.string()?;
                let value = match s.as_ref() {
                    $($canonical $(| $alias)* => $ty::$variant,)+
                    other => {
                        return Err(::nextjson::Error::custom(
                            format!("invalid {} value: {other}", stringify!($ty)),
                        )
                        .into());
                    }
                };
                out.write(value);
                Ok(())
            }
        }
    };
}

pub mod address;
pub mod error;
pub mod transport;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "tuic")]
pub mod tuic;

#[cfg(feature = "tuic-quinn")]
#[path = "tuic-quinn/mod.rs"]
pub mod tuic_quinn;

pub use address::{Address, AddressType};
pub use error::{ProtocolError, Result};

pub mod prelude {
    pub use crate::address::{Address, AddressType};
    pub use crate::error::{ProtocolError, Result};

    pub use crate::transport::{
        GrpcConfig, GrpcMode, GrpcStream, GrpcTransport, H2Config, H2Stream, H2Transport,
        TlsConfig, TlsFingerprint, TlsStream, TlsTransport, TransportError, WebSocketConfig,
        WebSocketTransport, WsStream,
    };

    #[cfg(feature = "quic")]
    pub use crate::quic::prelude::*;

    #[cfg(feature = "tls")]
    pub use crate::tls::{TlsAcceptor, TlsConnector, TlsStream as TlsModuleStream};

    #[cfg(feature = "wireguard")]
    pub use crate::wireguard::{WireGuardError, WireGuardTunnel};

    #[cfg(feature = "tuic")]
    pub use crate::tuic::{TuicClient, TuicConnection, TuicServer};

    #[cfg(feature = "tuic-quinn")]
    pub use crate::tuic_quinn::{
        TuicQuinnConfig, TuicQuinnConnection, TuicQuinnEndpoint, TuicQuinnError,
    };
}
